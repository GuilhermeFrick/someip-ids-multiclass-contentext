#!/usr/bin/env python3
"""Features de comportamento de Service Discovery, sem valor de payload de aplicação.

experiments/bench-train mostrou que as features de CONTEÚDO da C1 (modelos de bytes,
entropia, mudança entre payloads) são a causa do falso positivo e da falta de
transferência entre domínios, e que as 5 features de tempo e tamanho transferem. Mas
nenhuma delas descreve o Service Discovery, e os quatro ataques do dataset do Kim são
ataques de SD (tools/attack_flows.py). Estas features usam só a semântica do protocolo
e da rede, que é a mesma em qualquer veículo; cada uma mira um mecanismo medido:

  sd_offer_rate_src     ofertas por segundo da origem (janela de 1 s). DoS e MITM single
                        anunciam a cada 20 ms e 10 ms; uma ECU legítima, a cada 2 s.
  svc_provider_count    origens distintas que ofereceram o serviço do pacote nos
                        últimos 10 s. Personificação: duas ECUs oferecendo 0x1001.
  sd_stopoffer_unicast  o pacote é SD com StopOffer (oferta com TTL 0) endereçado a um
                        nó, e não ao grupo multicast: o "a VDE parou" dirigido à ADAS.
  sd_endpoint_mismatch  o pacote é SD e alguma oferta anuncia um endpoint IPv4 que não é
                        o IP de origem: o StopOffer do .13 com os endpoints da VDE.
  ip_mac_conflict       o IP de origem já foi visto com outro MAC: o IP da VDE forjado
                        pelo .15. Um IDS numa porta espelhada vê o MAC.

O estado é por origem e por serviço, em janelas de tempo, e o cálculo é por pacote,
como o FeatureStreamer da C1, para poder ir ao sensor em C++ do mesmo jeito.
"""
import struct
from collections import defaultdict, deque

SD_NOMES = ["sd_offer_rate_src", "svc_provider_count", "sd_stopoffer_unicast",
            "sd_endpoint_mismatch", "ip_mac_conflict"]
JANELA_OFERTAS = 1.0
JANELA_PROVEDORES = 10.0


def sd_entradas(raw):
    """(entradas, endpoints) de um quadro UDP de SD: entradas (tipo, serviço, ttl, ip_do_endpoint)."""
    if len(raw) < 42 or raw[12:14] != b"\x08\x00" or raw[23] != 17:
        return None
    ihl = (raw[14] & 0x0F) * 4
    c = raw[14 + ihl + 8:]
    if len(c) < 28 or c[0:2] != b"\xff\xff":
        return None
    pl = c[16:]
    n_ent = struct.unpack(">I", pl[4:8])[0]
    ent = pl[8:8 + n_ent]
    base = 8 + n_ent
    ops = []
    if base + 4 <= len(pl):
        n_op = struct.unpack(">I", pl[base:base + 4])[0]
        j = base + 4
        while j + 3 <= min(base + 4 + n_op, len(pl)):
            olen, otyp = struct.unpack(">HB", pl[j:j + 3])
            ops.append(bytes(pl[j + 4:j + 8]) if (otyp == 0x04 and j + 12 <= len(pl)) else None)
            j += 3 + olen
    saida = []
    for k in range(0, len(ent) - 15, 16):
        typ, i1, nops = ent[k], ent[k + 1], ent[k + 3] >> 4
        svc = struct.unpack(">H", ent[k + 4:k + 6])[0]
        ttl = int.from_bytes(ent[k + 9:k + 12], "big")
        ips = [o for o in ops[i1:i1 + nops] if o is not None]
        saida.append((typ, svc, ttl, ips))
    return saida


class SdStreamer:
    """Estado e cálculo das 5 features de SD, pacote a pacote."""

    def __init__(self):
        self.ofertas = defaultdict(deque)        # origem -> instantes das ofertas recentes
        self.provedores = defaultdict(dict)      # serviço -> {origem: último instante}
        self.mac_do_ip = {}                      # ip -> mac visto primeiro

    def step(self, raw, src, dst, svc_pacote, ts):
        mac = bytes(raw[6:12])
        conflito = 0.0
        visto = self.mac_do_ip.get(src)
        if visto is None:
            self.mac_do_ip[src] = mac
        elif visto != mac:
            conflito = 1.0

        unicast_stop = 0.0
        mismatch = 0.0
        servico = svc_pacote
        ents = sd_entradas(raw)
        fila = self.ofertas[src]
        if ents is not None:
            src_b = bytes(raw[26:30])
            multicast = 224 <= raw[30] <= 239
            for typ, svc, ttl, ips in ents:
                if typ != 0x01:
                    continue
                servico = svc
                if ttl > 0:
                    fila.append(ts)
                    self.provedores[svc][src] = ts
                elif not multicast:
                    unicast_stop = 1.0
                if any(ip != src_b for ip in ips):
                    mismatch = 1.0
        while fila and ts - fila[0] > JANELA_OFERTAS:
            fila.popleft()
        taxa = len(fila) / JANELA_OFERTAS

        prov = self.provedores.get(servico)
        n_prov = 0.0
        if prov:
            for s in [s for s, t in prov.items() if ts - t > JANELA_PROVEDORES]:
                del prov[s]
            n_prov = float(len(prov))
        return (taxa, n_prov, unicast_stop, mismatch, conflito)

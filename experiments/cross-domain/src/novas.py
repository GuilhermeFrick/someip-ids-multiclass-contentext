"""Features candidatas novas (fase 2). Cada uma tem a hipótese escrita ANTES da medição
(RELATORIO.md, seção 4). Política de cabeçalho: IP, MAC, serviço e sessão aparecem só como
CHAVE de agrupamento (estado por origem, por par), nunca como valor de entrada do modelo.

Contexto de origem: as features src_* valem para TODOS os pacotes da origem (inclusive ACKs
TCP), como a src_payload_div da C1. A origem é o MAC (raw[6:12]): o IP pode ser forjado
(MITM multi, .15 com o IP da VDE), o MAC é o que a placa do atacante escreve.

  src_svc_offered     serviços distintos oferecidos (TTL>0) pela origem nos últimos 10 s.
  sd_n_entries        número de entradas na mensagem SD (0 se não é SD).
  src_tcp_ctrl_rate   segmentos TCP com SYN, FIN ou RST enviados pela origem no último 1 s.
  implaus_frac        fração dos campos double (payload múltiplo de 8 B) implausíveis para um
                      sinal físico: não finito, ou |x| fora de [1e-9, 1e9] com x != 0.
  src_implaus_frac    fração das mensagens com payload da origem, no último 1 s, com algum
                      campo implausível.
  relay_role          1 se a origem RECEBEU (MAC de destino) e ENVIOU notificações nos últimos 2 s.
  sd_sess_break       SD: o session ID do cabeçalho SOME/IP não é o anterior + 1 no par
                      (IP origem, IP destino). Usa a RELAÇÃO entre sessões consecutivas, não o valor.
  src_sd_frac         fração dos pacotes da origem, no último 1 s, que são SD.
  src_stopoffer_rate  StopOffers (oferta com TTL 0) enviados pela origem no último 1 s.
"""
import math
import struct
from collections import defaultdict, deque

import numpy as np

NOVAS_NOMES = ["src_svc_offered", "sd_n_entries", "src_tcp_ctrl_rate", "implaus_frac",
               "src_implaus_frac", "relay_role", "sd_sess_break", "src_sd_frac", "src_stopoffer_rate"]
J1, J2, J10 = 1.0, 2.0, 10.0
NOTIF = 0x02
OFFER = 0x01


def _expira(fila, ts, jan):
    while fila and ts - fila[0][0] > jan:
        fila.popleft()


class NovasStreamer:
    def __init__(self):
        self.svc_of = defaultdict(dict)          # mac -> {svc: último ts}
        self.ctrl = defaultdict(deque)           # mac -> (ts,)
        self.impl = defaultdict(deque)           # mac -> (ts, 0/1)
        self.rx = {}                             # mac -> último ts em que recebeu notificação
        self.tx = {}                             # mac -> último ts em que enviou notificação
        self.sess = {}                           # (ip src, ip dst) -> último session id SD
        self.sdq = defaultdict(deque)            # mac -> (ts, is_sd)
        self.sdsum = defaultdict(float)
        self.implsum = defaultdict(float)
        self.stopq = defaultdict(deque)          # mac -> (ts,)

    def step(self, p, raw):
        ts = p.ts
        mac = bytes(raw[6:12])
        dmac = bytes(raw[0:6])
        # --- SD ---
        n_ent = 0
        brk = 0.0
        if p.is_sd:
            n_ent = len(p.sd_entries)
            so = self.svc_of[mac]
            for (et, sid, _iid, ttl) in p.sd_entries:
                if et == OFFER:
                    if ttl > 0:
                        so[sid] = ts
                    else:
                        self.stopq[mac].append((ts,))
            if len(p.pl_l4) >= 12:
                s = int.from_bytes(p.pl_l4[10:12], "big")
                k = (p.src, p.dst)
                ant = self.sess.get(k)
                if ant is not None:
                    esperado = ant + 1 if ant < 0xFFFF else 1
                    brk = 0.0 if s == esperado else 1.0
                self.sess[k] = s
        so = self.svc_of.get(mac)
        n_svc = 0.0
        if so:
            for s in [s for s, t in so.items() if ts - t > J10]:
                del so[s]
            n_svc = float(len(so))
        # --- TCP de controle ---
        fc = self.ctrl[mac]
        if p.proto == 6:
            ihl = (raw[14] & 0x0F) * 4
            fl = raw[14 + ihl + 13] if len(raw) > 14 + ihl + 13 else 0
            if fl & 0x07:                       # FIN=1, SYN=2, RST=4
                fc.append((ts,))
        _expira(fc, ts, J1)
        ctrl_rate = len(fc) / J1
        # --- plausibilidade de doubles ---
        impl = 0.0
        pl = p.pl_someip
        if p.is_someip and not p.is_sd and pl:
            if len(pl) >= 8 and len(pl) % 8 == 0:
                x = np.frombuffer(pl, dtype="<f8")
                with np.errstate(invalid="ignore", over="ignore"):
                    ax = np.abs(x)
                    ruim = ~np.isfinite(x) | ((ax != 0) & ((ax < 1e-9) | (ax > 1e9)))
                impl = float(ruim.mean())
            v = 1.0 if impl > 0 else 0.0
            self.impl[mac].append((ts, v))
            self.implsum[mac] += v
        fi = self.impl[mac]
        while fi and ts - fi[0][0] > J1:
            self.implsum[mac] -= fi.popleft()[1]
        src_impl = (self.implsum[mac] / len(fi)) if fi else 0.0
        # --- papel de repasse ---
        if p.is_someip and not p.is_sd and p.msg_type == NOTIF:
            self.tx[mac] = ts
            self.rx[dmac] = ts
        r, t = self.rx.get(mac), self.tx.get(mac)
        relay = 1.0 if (r is not None and t is not None and ts - r <= J2 and ts - t <= J2) else 0.0
        # --- fração de SD da origem ---
        fs = self.sdq[mac]
        v = 1.0 if p.is_sd else 0.0
        fs.append((ts, v))
        self.sdsum[mac] += v
        while fs and ts - fs[0][0] > J1:
            self.sdsum[mac] -= fs.popleft()[1]
        sd_frac = max(self.sdsum[mac], 0.0) / len(fs)
        # --- StopOffers da origem ---
        fq = self.stopq[mac]
        _expira(fq, ts, J1)
        stop_rate = len(fq) / J1
        return (n_svc, float(n_ent), ctrl_rate, impl, src_impl, relay, brk, sd_frac, stop_rate)

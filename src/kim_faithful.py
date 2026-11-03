"""Extrator FIEL às 12 features publicadas por Kim et al. (Systems 2026, 14, 196).

O artigo não traz código e omite detalhes que mudam o valor das features. Esta versão foi
recuperada por engenharia reversa dos vetores que os autores publicaram (X_train.npy /
X_test.npy no Figshare): alinhando as linhas com o benign_traffic.pcap, cada coluna abaixo
reproduz a do Kim com resíduo na precisão do float32 (docs/kim-engenharia-reversa.md).

O que o artigo não diz e o extrator dele faz:
  - "pacote anterior" é SEMPRE o pacote anterior da captura inteira, não o do mesmo fluxo;
  - o primeiro pacote de cada captura é descartado (não tem anterior);
  - o modelo de bytes é ajustado com a visão de TODOS os pacotes do arquivo benigno (menos
    o primeiro), inclusive os sem payload, cada visão completada com zeros (ou truncada)
    até L = 64 bytes; o escore soma as 64 posições do vetor completado; entropia = -logL/64;
  - o payload SOME/IP inclui o de SD; a "visão SD" é só o array de opções da mensagem SD,
    com o campo de comprimento (Find e SubscribeAck, sem opções, viram zeros);
  - Hamming = bits de int(a) XOR int(b): os payloads se alinham pelo FIM;
  - a variação de comprimento TCP/UDP só existe entre dois pacotes UDP seguidos.

Colunas, na ordem dos .npy do Kim:
  0 l4_loglik     1 l4_entropy     2 someip_loglik   3 sd_loglik    4 someip_entropy
  5 sd_entropy    6 sd_hamming     7 ip_len_change   8 udp_len_change
  9 time_interval 10 l4_hamming   11 someip_hamming
A coluna 8 vale -9999 quando não se aplica (pacote TCP de um lado): é o sentinela do Kim, que
vira o mínimo da coluna e, normalizado, 0.
"""
from __future__ import annotations

import struct

import numpy as np

L = 64
ALPHA = 1.0
SD_PORT = 30490
UDP_NA = -9999.0
FEATURE_NAMES = ["l4_loglik", "l4_entropy", "someip_loglik", "sd_loglik", "someip_entropy",
                 "sd_entropy", "sd_hamming", "ip_len_change", "udp_len_change",
                 "time_interval", "l4_hamming", "someip_hamming"]


def read_pcap(path):
    """Leitor de PCAP clássico sem dependências: gera (ts, bytes do quadro)."""
    with open(path, "rb") as fh:
        cab = fh.read(24)
        magic = struct.unpack("<I", cab[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end = "<"
        else:
            end = ">"
            magic = struct.unpack(">I", cab[:4])[0]
        div = 1e9 if magic == 0xA1B23C4D else 1e6
        while True:
            reg = fh.read(16)
            if len(reg) < 16:
                return
            sec, frac, incl, _ = struct.unpack(end + "IIII", reg)
            yield sec + frac / div, fh.read(incl)


def views(raw):
    """Visões de um quadro Ethernet/IPv4/TCP|UDP, ou None se não for TCP/UDP sobre IPv4.

    Devolve (proto, ip_len, l4, someip, sd_opts): l4 é o payload de transporte (com o
    cabeçalho SOME/IP), someip o que vem depois dos 16 bytes do cabeçalho SOME/IP (inclui
    SD) e sd_opts o array de opções da mensagem SD com o campo de comprimento."""
    if len(raw) < 34 or raw[12:14] != b"\x08\x00" or raw[23] not in (6, 17):
        return None
    proto = raw[23]
    ihl = (raw[14] & 0x0F) * 4
    ip_len = int.from_bytes(raw[16:18], "big")
    l4o = 14 + ihl
    if proto == 17:
        off = l4o + 8
        sport = int.from_bytes(raw[l4o:l4o + 2], "big")
        dport = int.from_bytes(raw[l4o + 2:l4o + 4], "big")
    else:
        off = l4o + (raw[l4o + 12] >> 4) * 4
        sport = dport = 0
    l4 = bytes(raw[off:14 + ip_len]) if ip_len else bytes(raw[off:])
    someip = sd = b""
    if len(l4) >= 16:
        someip = l4[16:]
        svc = int.from_bytes(l4[0:2], "big")
        if dport == SD_PORT or sport == SD_PORT or svc == 0xFFFF:
            if len(someip) >= 8:
                ne = int.from_bytes(someip[4:8], "big")
                sd = someip[8 + ne:]
    return proto, ip_len, l4, someip, sd


class PaddedByteModel:
    """Modelo posicional das Eq. 2-6 como o Kim o aplicou: visão completada com zeros até L."""

    def __init__(self, length=L, alpha=ALPHA):
        self.L = length
        self.alpha = alpha
        self.counts = np.zeros((length, 256))
        self.n = 0
        self.logp = None
        self._cache = {}

    def _vec(self, b):
        return np.frombuffer(b[:self.L].ljust(self.L, b"\x00"), np.uint8)

    def update(self, b, weight=1):
        self.counts[np.arange(self.L), self._vec(b)] += weight
        self.n += weight

    def finalize(self):
        self.logp = np.log((self.counts + self.alpha) / (self.n + 256 * self.alpha))
        self._cache = {}
        return self

    def loglik(self, b):
        v = self._cache.get(b)
        if v is None:
            v = float(self.logp[np.arange(self.L), self._vec(b)].sum())
            self._cache[b] = v
        return v


def fit_models(benign_pcap):
    """Ajusta os três modelos (L4, SOME/IP, SD) no arquivo benigno inteiro, menos o 1º pacote."""
    from collections import Counter
    acc = [Counter(), Counter(), Counter()]
    primeiro = True
    for _, raw in read_pcap(benign_pcap):
        v = views(raw)
        if v is None:
            continue
        if primeiro:
            primeiro = False
            continue
        for k, b in enumerate(v[2:]):
            acc[k][b] += 1
    models = []
    for c in acc:
        m = PaddedByteModel()
        for b, n in c.items():
            m.update(b, n)
        models.append(m.finalize())
    return models


def _bits(a, b):
    return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")


def extract(pcap, models):
    """Features brutas (não normalizadas) de um PCAP, uma linha por pacote TCP/UDP, sem o 1º.

    Devolve (X, ts, mac_origem, ip_origem), com os dois últimos em bytes, para rotular."""
    ml4, mso, msd = models
    rows, tss, macs, ips = [], [], [], []
    prev = None
    for ts, raw in read_pcap(pcap):
        v = views(raw)
        if v is None:
            continue
        proto, ip_len, l4, so, sd = v
        if prev is not None:
            pts, pproto, pip, pl4, pso, psd = prev
            a, b, c = ml4.loglik(l4), mso.loglik(so), msd.loglik(sd)
            udp = (len(l4) - len(pl4)) if (proto == 17 and pproto == 17) else UDP_NA
            rows.append((a, -a / L, b, c, -b / L, -c / L, _bits(sd, psd), ip_len - pip, udp,
                         ts - pts, _bits(l4, pl4), _bits(so, pso)))
            tss.append(ts)
            macs.append(bytes(raw[6:12]))
            ips.append(bytes(raw[26:30]))
        prev = (ts, proto, ip_len, l4, so, sd)
    return np.array(rows, dtype=np.float64), np.array(tss), macs, ips


def normalize(X, lo, hi):
    """Min-max com os limites dados (os do conjunto inteiro, como o Kim)."""
    span = np.where(hi > lo, hi - lo, 1.0)
    return (X - lo) / span

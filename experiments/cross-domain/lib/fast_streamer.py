#!/usr/bin/env python3
"""Versão rápida, e EXATAMENTE igual, do FeatureStreamer da C1 para extração em lote.

Medido no runner (100 mil pacotes do Kim): 46 us por pacote no FeatureStreamer, quase tudo em
dois pontos que não mudam o resultado:
  * src_payload_div refaz set() de até 1000 payloads a cada pacote: aqui a contagem de
    distintos da janela é incremental (Counter + deque), o mesmo número;
  * o modelo de bytes recalcula loglik e entropia de payloads que se repetem milhares de
    vezes: aqui o resultado fica numa memória por payload (limpa quando passa de LIMITE).
O código de referência (extract_ext.py, usado na paridade com o sensor em C++) não muda.
check_fast_streamer() compara as duas versões pacote a pacote.
"""
from collections import Counter, defaultdict, deque

LIMITE = 200000


class _Memo:
    def __init__(self, modelo):
        self.m, self.ll, self.ce = modelo, {}, {}

    def loglik(self, b):
        v = self.ll.get(b)
        if v is None:
            if len(self.ll) > LIMITE:
                self.ll.clear()
            v = self.ll[b] = self.m.loglik(b)
        return v

    def cross_entropy(self, b):
        v = self.ce.get(b)
        if v is None:
            if len(self.ce) > LIMITE:
                self.ce.clear()
            v = self.ce[b] = self.m.cross_entropy(b)
        return v


def memoriza(bms):
    """Envolve um dict de modelos de bytes ({"someip": ..., "sd": ..., "l4": ...})."""
    return {k: _Memo(v) for k, v in bms.items()}


def classe_rapida(extract_ext):
    """Subclasse do FeatureStreamer de referência com src_payload_div incremental."""
    hamming = extract_ext.hamming
    flow_key = extract_ext.someip.flow_key

    class FeatureStreamerRapido(extract_ext.FeatureStreamer):
        def __init__(self):
            super().__init__()
            self.src_cnt = defaultdict(Counter)

        def step(self, p, models):
            fk = flow_key(p)
            st = self.last.get(fk)
            if st is None:
                iat = 0.0; ip_len_chg = 0; l4_len_chg = 0
                someip_chg = sd_chg = l4_chg = 0
            else:
                iat = p.ts - st["ts"]
                ip_len_chg = p.ip_len - st["ip_len"]
                l4_len_chg = len(p.pl_l4) - len(st["l4"])
                l4_chg = hamming(p.pl_l4, st["l4"])
                someip_chg = hamming(p.pl_someip, st["someip"]) if (p.pl_someip or st["someip"]) else 0
                sd_chg = hamming(p.pl_sd, st["sd"]) if (p.pl_sd or st["sd"]) else 0
            someip_ll = models["someip"].loglik(p.pl_someip) if p.pl_someip else 0.0
            sd_ll = models["sd"].loglik(p.pl_sd) if p.pl_sd else 0.0
            l4_ll = models["l4"].loglik(p.pl_l4) if p.pl_l4 else 0.0
            someip_h = models["someip"].cross_entropy(p.pl_someip) if p.pl_someip else 0.0
            sd_h = models["sd"].cross_entropy(p.pl_sd) if p.pl_sd else 0.0
            l4_h = models["l4"].cross_entropy(p.pl_l4) if p.pl_l4 else 0.0
            h = self.recent_pld[fk]
            repeat_rate = (sum(1 for q in h if q == p.pl_someip) / len(h)) if (h and p.pl_someip) else 0.0
            h.append(p.pl_someip)
            someip_len = float(len(p.pl_someip))
            l4_len = float(len(p.pl_l4))
            wp = self.src_pld[p.src]
            cnt = self.src_cnt[p.src]
            if p.pl_someip:
                if len(wp) == wp.maxlen:
                    velho = wp[0]
                    cnt[velho] -= 1
                    if not cnt[velho]:
                        del cnt[velho]
                wp.append(p.pl_someip)
                cnt[p.pl_someip] += 1
            src_payload_div = (len(cnt) / len(wp)) if len(wp) > 1 else 0.0
            self.last[fk] = {"ts": p.ts, "ip_len": p.ip_len, "l4": p.pl_l4,
                             "someip": p.pl_someip, "sd": p.pl_sd}
            return (iat, someip_ll, sd_ll, l4_ll, someip_h, sd_h, l4_h,
                    someip_chg, sd_chg, l4_chg, ip_len_chg, l4_len_chg,
                    repeat_rate, someip_len, l4_len, src_payload_div)

    return FeatureStreamerRapido


def check_fast_streamer(pcap, bms, ref, extract_ext, n=200000):
    """Compara a versão de referência e a rápida nos n primeiros pacotes; devolve (n, iguais)."""
    import itertools
    import train_bench as tb
    a, b = extract_ext.FeatureStreamer(), classe_rapida(extract_ext)()
    mb = memoriza(bms)
    tot = iguais = 0
    for p, _c, _r in itertools.islice(tb.pacotes(pcap, {}, ref), n):
        tot += 1
        iguais += a.step(p, bms) == b.step(p, mb)
    return tot, iguais

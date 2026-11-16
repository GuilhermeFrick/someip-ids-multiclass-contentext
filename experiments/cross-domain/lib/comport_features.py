#!/usr/bin/env python3
"""Features de comportamento dos sinais, sem decorar valores (detector B).

O modelo de bytes da C1 aprende QUAIS valores aparecem no treino; um sinal que passa a variar
vira "ataque" (scripts/kim_mutacao.py no repositório da C1: FP de 0,04% para 10,6% só fazendo
um campo do VDE variar). Estas features olham COMO cada sinal chega, comparando cada mensagem
com o histórico do próprio fluxo de dados, calibrado online (sem estatística do treino):

  rate_rel          intervalo desde a mensagem anterior do mesmo fluxo de dados (origem,
                    destino, serviço, evento) dividido pelo intervalo típico desse fluxo (média
                    móvel). Normal ~1; rajada (DoS) << 1.
  dup_window        mensagens com payload idêntico ao atual vindas do mesmo fluxo no último
                    segundo. Inundação de conteúdo repetido.
  jump_rel          verossimilhança em relação ao anterior: para cada campo do payload (double
                    quando o tamanho fecha em 8 bytes, senão byte), |x - x_anterior| dividida
                    pela variação típica daquele campo (média móvel); vale o maior campo, em
                    log1p. Não importa o valor, só se a variação é incomum para aquele campo.
                    Valor não finito (NaN/inf, típico de payload aleatório) conta como salto máximo.
  changed_frac      fração dos campos que mudaram em relação à mensagem anterior.
  pub_count_evt     origens distintas que publicaram o mesmo (serviço, evento) nos últimos 2 s.
                    Duas fontes do mesmo dado: personificação ou relay.

Pacotes sem mensagem SOME/IP de aplicação (SD, ACK, segmento sem cabeçalho) recebem 0 nas
cinco, exceto pub_count_evt, que fica 0 também. O cálculo é por pacote, como o FeatureStreamer.
"""
import math
import struct
from collections import defaultdict, deque

import numpy as np

COMP_NOMES = ["rate_rel", "dup_window", "jump_rel", "changed_frac", "pub_count_evt"]
ALFA = 0.05            # peso da média móvel do intervalo e da variação típica
JANELA_DUP = 1.0
JANELA_PUB = 2.0
SALTO_MAX = 1e6


def _campos(pl):
    if len(pl) >= 8 and len(pl) % 8 == 0:
        return np.frombuffer(pl, dtype="<f8").astype(np.float64)
    return np.frombuffer(pl, dtype=np.uint8).astype(np.float64)


class CompStreamer:
    def __init__(self):
        self.fluxo = {}                              # chave -> estado do fluxo de dados
        self.dups = defaultdict(deque)               # chave -> (ts, payload) recentes
        self.pubs = defaultdict(dict)                # (svc, evento) -> {origem: último ts}

    def step(self, p):
        if not getattr(p, "is_someip", False) or getattr(p, "is_sd", False):
            return (0.0, 0.0, 0.0, 0.0, 0.0)
        pl = p.pl_someip
        chave = (p.src, p.dst, p.service_id, p.method_id)
        ts = p.ts

        # publicadores do mesmo (serviço, evento)
        pub = self.pubs[(p.service_id, p.method_id)]
        pub[p.src] = ts
        for s in [s for s, t in pub.items() if ts - t > JANELA_PUB]:
            del pub[s]
        n_pub = float(len(pub))

        # repetição do mesmo payload na janela
        fila = self.dups[chave]
        while fila and ts - fila[0][0] > JANELA_DUP:
            fila.popleft()
        dup = float(sum(1 for _, q in fila if q == pl))
        fila.append((ts, pl))
        if len(fila) > 4096:
            fila.popleft()

        x = _campos(pl) if pl else None
        st = self.fluxo.get(chave)
        if st is None:
            self.fluxo[chave] = {"ts": ts, "dt": None, "x": x, "esc": None}
            return (1.0, dup, 0.0, 0.0, n_pub)

        dt = ts - st["ts"]
        rate = 1.0 if st["dt"] is None else dt / max(st["dt"], 1e-6)
        st["dt"] = dt if st["dt"] is None else (1 - ALFA) * st["dt"] + ALFA * dt
        st["ts"] = ts

        salto, frac = 0.0, 0.0
        xa = st["x"]
        if x is not None and xa is not None and len(x) == len(xa) and len(x) > 0:
            with np.errstate(invalid="ignore", over="ignore"):
                d = np.abs(x - xa)
            nao_finito = ~np.isfinite(d)
            frac = float(np.mean((d != 0) | nao_finito))
            esc = st["esc"]
            if esc is None or len(esc) != len(d):
                esc = np.zeros(len(d))
            ref = esc + 1e-9 + 1e-6 * np.where(np.isfinite(xa), np.abs(xa), 0.0)
            with np.errstate(invalid="ignore", over="ignore", divide="ignore"):
                z = np.where(nao_finito, SALTO_MAX, np.minimum(d / ref, SALTO_MAX))
            salto = math.log1p(float(z.max()))
            dd = np.where(nao_finito, 0.0, np.minimum(d, 1e12))
            st["esc"] = (1 - ALFA) * esc + ALFA * dd
        elif x is not None and xa is not None:
            salto, frac = math.log1p(SALTO_MAX), 1.0      # mudou o formato do payload
        st["x"] = x
        return (float(min(rate, 1e6)), dup, salto, frac, n_pub)

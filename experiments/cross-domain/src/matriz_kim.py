#!/usr/bin/env python3
"""Matriz entre domínios do detector BINÁRIO de Kim et al. (baseline), no mesmo protocolo da C1.

Modelo: as 12 features de Kim calculadas pelo extrator fiel (src/kim_faithful.py, recuperado dos
vetores publicados pelos autores) e um XGBoost binário com os hiperparâmetros do artigo de Kim
(1.000 árvores, profundidade 6, eta 0,05, subsample e colsample 0,8; scripts/kim_experiments.py),
com o limiar de decisão do artigo (0,36). Saída binária: normal x ataque.

Domínios (cada um com as mesmas 7 capturas):
  kim     β, o dataset de Kim (K.KIM_DIR);
  gama    γ, gerado pela bancada com o conteúdo do CARLA, veículo andando (K.GAMA_DIR);
  parado  gerado pela mesma bancada com o conteúdo do benigno de Kim, veículo parado (PARADO_DIR,
          opcional: sem ele, a matriz fica 2 x 2).

Protocolo (o mesmo de matriz_c1.py), para cada domínio de TREINO d:
  - o modelo de bytes (3 visões: L4, SOME/IP, SD) é ajustado nos 70% iniciais da captura benigna
    de d; as features de TODOS os domínios são calculadas com ele;
  - treino nos 70% iniciais de cada captura de d, com a normalização min-max desse treino;
  - teste nos 30% finais de cada captura de cada domínio, sem nenhum reajuste.
Rótulos: kim pela regra do próprio Kim (artefatos/kim_attack_idx.npz: índices, entre as linhas do
extrator fiel, dos pacotes que ele rotulou como ataque, recuperados dos vetores publicados por
scripts/kim_label_rule.py), usada no treino; também reportado pelo MAC. Os outros, pelo MAC do
atacante (injector.mac).

Uso:
  python3 src/matriz_kim.py --jobs 7 --nthread 8 [--economiza]
--economiza apaga as features de um domínio de treino depois de usá-las (pouco disco).
Saídas: WORK/matriz_kim.json e WORK/matriz_kim.md.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import argparse
import json
import os
import shutil
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import numpy as np

sys.path.insert(0, K.C1_SRC)
import kim_faithful as kf  # noqa: E402

OUT = os.path.join(K.WORK, "kim")
KIM_LABELS = os.environ.get("KIM_LABELS", os.path.join(K.WORK, "kim_labels"))
DIRS = {"kim": K.KIM_DIR, "gama": K.GAMA_DIR, "parado": os.environ.get("PARADO_DIR", "")}
SIGLA = {"kim": "β", "gama": "γ", "parado": "γ-parado"}
ORDEM = ["benign", "dos", "fuzzy1", "fuzzy2", "fuzzy3", "mitm_multi", "mitm_single"]
KIM_ARQ = {"benign": "benign_traffic.pcap", "dos": "dos_noti_flood.pcap",
           "fuzzy1": "fuzzy_sd_offer_rand_noti(1).pcap", "fuzzy2": "fuzzy_sd_offer_rand_noti(2).pcap",
           "fuzzy3": "fuzzy_sd_offer_rand_noti(3).pcap", "mitm_multi": "mitm_multi_attacker.pcap",
           "mitm_single": "mitm_single_attacker.pcap"}
# MACs dos atacantes no dataset de Kim (manifest.py); nos gerados, os de injector.mac
KIM_MACS = {"dos": ["02:42:ac:12:00:0b"], "fuzzy1": ["02:42:ac:12:00:11"], "fuzzy2": ["02:42:ac:12:00:0c"],
            "fuzzy3": ["02:42:ac:12:00:0c"], "mitm_multi": ["02:42:ac:12:00:0e", "02:42:ac:12:00:0f"],
            "mitm_single": ["02:42:ac:12:00:0d"]}
PARAMS = dict(objective="binary:logistic", eta=0.05, max_depth=6, subsample=0.8, colsample_bytree=0.8,
              reg_lambda=1.0, gamma=0.0, min_child_weight=1, tree_method="hist", eval_metric="auc", seed=42)
N_TREES = 1000
LIMIAR = 0.36
FRAC = 0.7
Y_MAC = ".y_mac.npy"


def dominios():
    return [d for d in ("kim", "gama", "parado") if DIRS[d] and os.path.isdir(DIRS[d])]


def pcap_de(dom, nome):
    return os.path.join(DIRS[dom], KIM_ARQ[nome]) if dom == "kim" else os.path.join(DIRS[dom], nome, "scn.pcap")


def macs_ataque(dom, nome):
    if dom == "kim":
        return {m.replace(":", "") for m in KIM_MACS.get(nome, [])}
    p = os.path.join(DIRS[dom], nome, "injector.mac")
    return {ln.split()[0].replace(":", "").lower() for ln in open(p) if ln.strip()} if os.path.exists(p) else set()


class Modelo:
    """kf.PaddedByteModel sem o cache ilimitado (nos domínios gerados quase todo payload é distinto)."""

    def __init__(self, logp):
        self.logp = logp
        self.idx = np.arange(kf.L)
        self.cache = {}

    def loglik(self, b):
        v = self.cache.get(b)
        if v is None:
            v = float(self.logp[self.idx, np.frombuffer(b[:kf.L].ljust(kf.L, b"\x00"), np.uint8)].sum())
            if len(self.cache) > 200000:
                self.cache.clear()
            self.cache[b] = v
        return v


def ajusta_bm(dom):
    """Modelos de bytes nos 70% iniciais (menos o 1º pacote) do benigno do domínio (scripts/kim_experiments.py)."""
    from collections import Counter
    vs = [v for _, raw in kf.read_pcap(pcap_de(dom, "benign")) if (v := kf.views(raw)) is not None][1:]
    k = int(FRAC * len(vs))
    logps = []
    for j in (2, 3, 4):
        m = kf.PaddedByteModel()
        for b, n in Counter(v[j] for v in vs[:k]).items():
            m.update(b, n)
        logps.append(m.finalize().logp)
    return np.stack(logps)


def base_de(dom, nome):
    return os.path.join(OUT, "feats", dom, nome)


def extrai_um(tarefa):
    """Uma passada no PCAP: as 12 features com o modelo de bytes do domínio bm (como kf.extract)."""
    dom, nome, bm = tarefa
    from array import array
    t0 = time.time()
    ml4, mso, msd = [Modelo(lp) for lp in np.load(os.path.join(OUT, "bm_%s.npy" % bm))]
    L = kf.L
    rows = array("d")
    atk = macs_ataque(dom, nome)
    ymac = array("b")
    prev = None
    for ts, raw in kf.read_pcap(pcap_de(dom, nome)):
        v = kf.views(raw)
        if v is None:
            continue
        proto, ip_len, l4, so, sd = v
        if prev is not None:
            pts, pproto, pip, pl4, pso, psd = prev
            udp = (len(l4) - len(pl4)) if (proto == 17 and pproto == 17) else kf.UDP_NA
            a, b, c = ml4.loglik(l4), mso.loglik(so), msd.loglik(sd)
            rows.extend((a, -a / L, b, c, -b / L, -c / L, kf._bits(sd, psd), ip_len - pip, udp, ts - pts,
                         kf._bits(l4, pl4), kf._bits(so, pso)))
            ymac.append(raw[6:12].hex() in atk)
        prev = (ts, proto, ip_len, l4, so, sd)
    base = base_de(dom, nome)
    os.makedirs(os.path.dirname(base), exist_ok=True)
    # float32, como o treino do Kim usa (scripts/kim_experiments.py)
    np.save(base + ".bm_%s.npy" % bm, np.frombuffer(rows, np.float64).reshape(-1, 12).astype(np.float32))
    if not os.path.exists(base + Y_MAC):
        np.save(base + Y_MAC, np.frombuffer(ymac, np.int8))
    return "%s/%s (modelo de bytes de %s): %d linhas, %.0f s" % (dom, nome, bm, len(ymac), time.time() - t0)


def carrega(dom, nome, bm):
    base = base_de(dom, nome)
    X = np.load(base + ".bm_%s.npy" % bm)
    y_mac = np.load(base + Y_MAC).astype(np.int64)
    y_kim = None
    if dom == "kim":
        y_kim = np.zeros(len(X), np.int64)
        if nome != "benign":
            p = os.path.join(KIM_LABELS, KIM_ARQ[nome] + ".kim_attack_idx.npy")
            # padrão: o artefato versionado (índices das linhas que o Kim rotulou como ataque)
            idx = np.load(p) if os.path.exists(p) else np.load(os.path.join(K.ARTEFATOS, "kim_attack_idx.npz"))[KIM_ARQ[nome]]
            assert idx.max() < len(X), (nome, idx.max(), len(X))
            y_kim[idx] = 1
    return X, y_mac, y_kim


def janelas(dom, bm):
    """{captura: (X, y_mac, y_kim)} em treino (70% iniciais) e teste (30% finais)."""
    tr, te = {}, {}
    for n in ORDEM:
        X, ym, yk = carrega(dom, n, bm)
        c = int(FRAC * len(X))
        tr[n] = (X[:c], ym[:c], None if yk is None else yk[:c])
        te[n] = (X[c:], ym[c:], None if yk is None else yk[c:])
    return tr, te


def norm(X, lo, hi):
    return ((X - lo) / np.where(hi > lo, hi - lo, 1.0)).astype(np.float32)


def treina(tr, rotulo, nthread):
    import xgboost as xgb
    X = np.concatenate([tr[n][0] for n in ORDEM])
    y = np.concatenate([tr[n][rotulo] for n in ORDEM])
    lo, hi = X.min(0), X.max(0)
    t0 = time.time()
    bst = xgb.train(dict(PARAMS, nthread=nthread), xgb.DMatrix(norm(X, lo, hi), label=y), N_TREES)
    print("   treino: %d linhas, %.1f%% ataque, %.0f s" % (len(y), 100 * y.mean(), time.time() - t0), flush=True)
    return bst, lo, hi


def avalia(bst, lo, hi, te, rotulo):
    import xgboost as xgb
    from sklearn.metrics import average_precision_score, roc_auc_score
    s = {n: bst.predict(xgb.DMatrix(norm(te[n][0], lo, hi))) for n in ORDEM}
    y = {n: te[n][rotulo] for n in ORDEM}
    S, Y = np.concatenate([s[n] for n in ORDEM]), np.concatenate([y[n] for n in ORDEM])
    P = S >= LIMIAR
    tp, fp, fn = int((P & (Y == 1)).sum()), int((P & (Y == 0)).sum()), int((~P & (Y == 1)).sum())
    prec, rec = tp / max(tp + fp, 1), tp / max(tp + fn, 1)
    out = {"roc_auc": float(roc_auc_score(Y, S)), "pr_auc": float(average_precision_score(Y, S)),
           "limiar": LIMIAR, "f1_ataque": 2 * prec * rec / max(prec + rec, 1e-12), "precisao_ataque": prec,
           "recall_ataque": rec, "fp_total": float(P[Y == 0].mean()), "por_captura": {}}
    for n in ORDEM:
        p, yy = s[n] >= LIMIAR, y[n]
        out["por_captura"][n] = {"fp": float(p[yy == 0].mean()) if (yy == 0).any() else None,
                                 "recall": float(p[yy == 1].mean()) if (yy == 1).any() else None,
                                 "normais": int((yy == 0).sum()), "ataque": int((yy == 1).sum())}
    return out


def tabelas(res, doms):
    cel = [(tr, te) for tr in doms for te in doms]
    nome = {c: "%s→%s" % (SIGLA[c[0]], SIGLA[c[1]]) for c in cel}

    def r(c):
        v = res["%s->%s" % c]
        return v["rotulo_kim"] if "rotulo_kim" in v else v

    L = ["**Kim binário (β com a regra de rótulo do Kim; os gerados pelo MAC)**", "",
         "| métrica | " + " | ".join(nome[c] for c in cel) + " |", "|---|" + "---:|" * len(cel)]
    for k in ("roc_auc", "pr_auc", "f1_ataque", "precisao_ataque", "recall_ataque"):
        L.append("| %s | %s |" % (k, " | ".join("%.4f" % r(c)[k] for c in cel)))
    L.append("| FP (todas) | %s |" % " | ".join("%.3f%%" % (100 * r(c)["fp_total"]) for c in cel))
    L += ["", "| FP por captura | " + " | ".join(nome[c] for c in cel) + " |", "|---|" + "---:|" * len(cel)]
    for n in ORDEM:
        L.append("| %s | %s |" % (n, " | ".join("%.3f%%" % (100 * r(c)["por_captura"][n]["fp"]) for c in cel)))
    L += ["", "| recall por captura | " + " | ".join(nome[c] for c in cel) + " |", "|---|" + "---:|" * len(cel)]
    for n in ORDEM[1:]:
        L.append("| %s | %s |" % (n, " | ".join("%.4f" % r(c)["por_captura"][n]["recall"] for c in cel)))
    if "kim" in doms:
        L += ["", "**Variante: β rotulado pelo MAC (mesmos modelos)**", "",
              "| métrica | " + " | ".join("%s→β" % SIGLA[d] for d in doms) + " |", "|---|" + "---:|" * len(doms)]
        for k in ("roc_auc", "pr_auc", "f1_ataque", "recall_ataque"):
            L.append("| %s | %s |" % (k, " | ".join("%.4f" % res["%s->kim" % d]["rotulo_mac"][k] for d in doms)))
        L.append("| FP (todas) | %s |" % " | ".join("%.3f%%" % (100 * res["%s->kim" % d]["rotulo_mac"]["fp_total"])
                                                   for d in doms))
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--nthread", type=int, default=8)
    ap.add_argument("--economiza", action="store_true")
    a = ap.parse_args()
    doms = dominios()
    print("domínios:", ", ".join("%s (%s)" % (SIGLA[d], DIRS[d]) for d in doms), flush=True)
    os.makedirs(OUT, exist_ok=True)
    res = {"modelo": "Kim binário: 12 features (kim_faithful), XGBoost %d árvores, profundidade %d, eta %.2f, "
                     "limiar %.2f" % (N_TREES, PARAMS["max_depth"], PARAMS["eta"], LIMIAR),
           "dominios": {d: DIRS[d] for d in doms}}
    for d in doms:
        print("== treino em %s" % SIGLA[d], flush=True)
        p = os.path.join(OUT, "bm_%s.npy" % d)
        if not os.path.exists(p):
            np.save(p, ajusta_bm(d))
        tarefas = [(t, n, d) for t in doms for n in ORDEM if not os.path.exists(base_de(t, n) + ".bm_%s.npy" % d)]
        with ProcessPoolExecutor(a.jobs) as ex:
            for msg in ex.map(extrai_um, tarefas):
                print("   " + msg, flush=True)
        tr, _ = janelas(d, d)
        bst, lo, hi = treina(tr, 2 if d == "kim" else 1, a.nthread)
        del tr
        for t in doms:
            _, te = janelas(t, d)
            if t == "kim":
                res["%s->%s" % (d, t)] = {"rotulo_kim": avalia(bst, lo, hi, te, 2),
                                         "rotulo_mac": avalia(bst, lo, hi, te, 1)}
                r = res["%s->%s" % (d, t)]["rotulo_kim"]
            else:
                res["%s->%s" % (d, t)] = r = avalia(bst, lo, hi, te, 1)
            print("   %s→%s: ROC-AUC %.4f PR-AUC %.4f F1 %.4f FP %.3f%%" % (
                SIGLA[d], SIGLA[t], r["roc_auc"], r["pr_auc"], r["f1_ataque"], 100 * r["fp_total"]), flush=True)
            del te
        if a.economiza:
            for t in doms:
                for n in ORDEM:
                    f = base_de(t, n) + ".bm_%s.npy" % d
                    if os.path.exists(f):
                        os.remove(f)
        json.dump(res, open(os.path.join(K.WORK, "matriz_kim.json"), "w"), indent=1)
    md = tabelas(res, doms)
    open(os.path.join(K.WORK, "matriz_kim.md"), "w").write(md)
    print(md)
    if a.economiza:
        shutil.rmtree(os.path.join(OUT, "feats"), ignore_errors=True)


if __name__ == "__main__":
    main()

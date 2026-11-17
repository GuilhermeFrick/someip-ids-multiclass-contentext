#!/usr/bin/env python3
"""Matriz entre domínios do detector C1 PUBLICADO (16 features), para as Tabelas XIII e XIV.

Cenários (teste sempre nos 30% finais de cada captura, pipeline.temporal_split):
  1. beta->beta    artefatos publicados como estão: results/features.npz (16 features já normalizadas
                   com results/minmax.npy, modelo de bytes results/bytemodels.npz) e results/model_16.json.
  2. beta->gama    o mesmo modelo, sem reajuste: features de gama com o modelo de bytes do Kim e a
                   normalização min-max do Kim.
  3. gama->gama    o mesmo PROCEDIMENTO em gama: modelo de bytes no benigno de gama (70% iniciais),
                   min-max do treino de gama, XGBClassifier com os hiperparâmetros do model_16.json,
                   treino nos 70% iniciais de cada captura.
  4. gama->beta    o modelo do cenário 3 aplicado, sem reajuste, aos 30% finais do Kim.
Se houver features do γ-parado (feats/parado/, PARADO_DIR), a matriz fica 3 x 3: o mesmo procedimento
com o modelo de bytes do γ-parado (feats/bm-parado.npz, colunas .bmP.npy), e cada modelo testado nos
três domínios (beta_parado, parado_parado, parado_beta, gama_parado, parado_gama).

Rótulos: beta com o rótulo da C1 (regra por IP, labeler.py) e também por MAC; gama por MAC (scn.labels).
Saída: matriz_c1.json e matriz_c1.md.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import json
import os
import sys

import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report

R = K.REPO
BASE = K.WORK
os.makedirs(os.path.join(BASE, "results"), exist_ok=True)
sys.path.insert(0, os.path.join(R, "src"))
import pipeline  # noqa: E402

CL = pipeline.CLASSES
ORDEM = ["benign", "dos", "fuzzy1", "fuzzy2", "fuzzy3", "mitm_multi", "mitm_single"]
COLS = json.load(open(os.path.join(BASE, "feats", "cols.json")))
BMIDX = [1, 2, 3, 4, 5, 6]           # posições das 6 features de modelo de bytes entre as 16


def norm(X, xmin, xmax):
    rng = np.where(xmax > xmin, xmax - xmin, 1.0)
    return ((X.astype(np.float64) - xmin) / rng).astype(np.float32)


SUFIXO = {"gama": ".bmG.npy", "parado": ".bmP.npy"}   # 6 colunas de modelo de bytes por domínio gerado
PFX = {"kim": "beta", "gama": "gama", "parado": "parado"}
SIGLA = {"kim": "β", "gama": "γ", "parado": "γ-parado"}


def carrega(dom, nome, bm):
    """16 features cruas; bm = domínio do modelo de bytes ('kim': o publicado; 'gama'/'parado': as 6
    colunas de bytes trocadas pelas do modelo daquele domínio)."""
    X = np.load(os.path.join(BASE, "feats", dom, nome + ".X.npy"), mmap_mode="r")
    A = np.array(X[:, :16], dtype=np.float32)
    if bm in SUFIXO:
        A[:, BMIDX] = np.load(os.path.join(BASE, "feats", dom, nome + SUFIXO[bm]))
    m = np.load(os.path.join(BASE, "feats", dom, nome + ".meta.npz"))
    return A, m["y_mac"].astype(np.int64), m["y_ip"].astype(np.int64)


XK = os.environ.get("XK_WORK", BASE)   # onde estão os .Xk.npy (extrai.py)


def carrega_k(dom, nome, kmin, kmax):
    """As 16 normalizadas com o min-max publicado, em precisão dupla e só então float32 (.Xk.npy),
    exatamente como results/features.npz; sem o arquivo, normaliza a partir do float32 (pode mudar
    o último dígito de algumas colunas e, com o modelo publicado, a classe de alguns pacotes)."""
    p = os.path.join(XK, "feats", dom, nome + ".Xk.npy")
    if os.path.exists(p):
        return np.load(p)
    return norm(carrega(dom, nome, "kim")[0], kmin, kmax)


def mede(pred_por, y_por, nomes):
    """pred_por / y_por: listas por captura (só a janela de teste)."""
    out = {"fp_por_captura": {}}
    for n, p, y in zip(nomes, pred_por, y_por):
        nor = y == 0
        out["fp_por_captura"][n] = {"fp": float(np.mean(p[nor] > 0)) if nor.any() else None,
                                    "normais": int(nor.sum()), "fp_quadros": int(np.sum(p[nor] > 0))}
    p, y = np.concatenate(pred_por), np.concatenate(y_por)
    rep = classification_report(y, p, labels=list(range(5)), target_names=CL, digits=4, output_dict=True,
                                zero_division=0)
    out["f1"] = {c: float(rep[c]["f1-score"]) for c in CL}
    out["recall"] = {c: float(rep[c]["recall"]) for c in CL}
    out["precisao"] = {c: float(rep[c]["precision"]) for c in CL}
    out["macro_f1"] = float(rep["macro avg"]["f1-score"])
    out["suporte"] = {c: int(rep[c]["support"]) for c in CL}
    out["fp_total"] = float(np.mean(p[y == 0] > 0))
    cm = np.bincount(y * 5 + p, minlength=25).reshape(5, 5)
    out["confusao"] = cm.tolist()
    return out


def main():
    res = {"notas": {}}
    # ---------- 1. beta -> beta (artefatos publicados) ----------
    b16 = xgb.Booster()
    b16.load_model(os.path.join(K.C1_ART, "model_16.json"))
    # a profundidade vem da ESTRUTURA das árvores: o campo max_depth da configuração salva no
    # artefato mostra o valor padrão (6), não o usado no treino (8; selecao_hiperparametros.json)
    arv = json.loads(b16.save_raw("json"))["learner"]["gradient_booster"]["model"]["trees"]

    def _prof(no, t):
        if t["left_children"][no] == -1:
            return 0
        return 1 + max(_prof(t["left_children"][no], t), _prof(t["right_children"][no], t))
    cfg = json.loads(b16.save_config())
    tp = cfg["learner"]["gradient_booster"]["tree_train_param"]
    hip = {"n_estimators": int(b16.num_boosted_rounds()), "max_depth": int(max(_prof(0, t) for t in arv)),
           "learning_rate": float(tp["eta"]), "max_bin": int(tp.get("max_bin", 256))}
    res["notas"]["hiperparametros_model_16"] = hip
    mm = np.load(os.path.join(K.C1_ART, "minmax.npy"))
    kmin, kmax = mm[0], mm[1]
    fpub = os.path.join(R, "results", "features.npz")
    if os.path.exists(fpub):
        # as features normalizadas que geraram o número publicado, quando estão no disco
        z = np.load(fpub, allow_pickle=True)
        Xn, yip, counts = z["Xn"], z["y"], [int(c) for c in z["counts"]]
        res["notas"]["beta_beta_fonte"] = "results/features.npz (publicado)"
    else:
        # sem o arquivo: a extração do Kim feita por extrai.py (modelo de bytes publicado),
        # normalizada com o minmax.npy publicado; é o mesmo cálculo do FeatureStreamer da C1
        partes, ys, counts = [], [], []
        for n in ORDEM:
            yi = np.load(os.path.join(BASE, "feats", "kim", n + ".meta.npz"))["y_ip"].astype(np.int64)
            partes.append(carrega_k("kim", n, kmin, kmax))
            ys.append(yi)
            counts.append(len(yi))
        Xn, yip = np.concatenate(partes), np.concatenate(ys)
        del partes, ys
        res["notas"]["beta_beta_fonte"] = "extrai.py (.Xk.npy: min-max publicado em precisão dupla)"
    ini = np.concatenate([[0], np.cumsum(counts)])
    kim_te = {}
    for i, n in enumerate(ORDEM):
        a, c = ini[i], ini[i] + int(counts[i] * 0.7)
        meta = np.load(os.path.join(BASE, "feats", "kim", n + ".meta.npz"))
        assert np.array_equal(meta["y_ip"], yip[ini[i]:ini[i + 1]])
        kim_te[n] = {"X": Xn[c:ini[i + 1]], "y_ip": yip[c:ini[i + 1]],
                     "y_mac": meta["y_mac"][int(counts[i] * 0.7):].astype(np.int64)}
    pk = {n: b16.predict(xgb.DMatrix(kim_te[n]["X"])).argmax(1) for n in ORDEM}
    res["beta_beta"] = {"rotulo_ip": mede([pk[n] for n in ORDEM], [kim_te[n]["y_ip"] for n in ORDEM], ORDEM),
                        "rotulo_mac": mede([pk[n] for n in ORDEM], [kim_te[n]["y_mac"] for n in ORDEM], ORDEM)}
    print("beta->beta (IP): macro-F1 %.4f" % res["beta_beta"]["rotulo_ip"]["macro_f1"],
          {c: round(v, 4) for c, v in res["beta_beta"]["rotulo_ip"]["f1"].items()}, flush=True)
    gerados = [d for d in ("gama", "parado") if os.path.isdir(os.path.join(BASE, "feats", d))
               and all(os.path.exists(os.path.join(BASE, "feats", d, n + ".meta.npz")) for n in ORDEM)]
    res["notas"]["dominios"] = ["kim"] + gerados
    # ---------- 2. beta -> cada domínio gerado (o modelo publicado, sem reajuste) ----------
    for t in gerados:
        pg, yg = [], []
        for n in ORDEM:
            A = carrega_k(t, n, kmin, kmax)
            ym = np.load(os.path.join(BASE, "feats", t, n + ".meta.npz"))["y_mac"].astype(np.int64)
            c = int(len(A) * 0.7)
            pg.append(b16.predict(xgb.DMatrix(A[c:])).argmax(1))
            yg.append(ym[c:])
        res["beta_" + PFX[t]] = mede(pg, yg, ORDEM)
        print("beta->%s: macro-F1 %.4f FP %.4f" % (t, res["beta_" + PFX[t]]["macro_f1"],
                                                    res["beta_" + PFX[t]]["fp_total"]), flush=True)
    # ---------- 3. treino em cada domínio gerado, teste em todos ----------
    par = pipeline.model_params(n_jobs=int(os.environ.get("NTHREAD", "4")))
    par.update(n_estimators=hip["n_estimators"], max_depth=hip["max_depth"], learning_rate=hip["learning_rate"],
               max_bin=hip["max_bin"])
    res["notas"]["parametros_treino_gerados"] = {k: v for k, v in par.items()}
    for d in gerados:
        g = {n: carrega(d, n, d) for n in ORDEM}
        Xtr = np.concatenate([g[n][0][:int(len(g[n][0]) * 0.7)] for n in ORDEM])
        ytr = np.concatenate([g[n][1][:int(len(g[n][0]) * 0.7)] for n in ORDEM])
        del g
        dmin, dmax = Xtr.min(0).astype(np.float64), Xtr.max(0).astype(np.float64)
        clf = xgb.XGBClassifier(**par)
        clf.fit(norm(Xtr, dmin, dmax), ytr)
        del Xtr, ytr
        clf.save_model(os.path.join(BASE, "results", "model_16_%s.json" % d))
        np.save(os.path.join(BASE, "results", "minmax_%s.npy" % d), np.vstack([dmin, dmax]))
        for t in ["kim"] + gerados:
            pr, yi, ym_ = [], [], []
            for n in ORDEM:
                A, ym, yip = carrega(t, n, d)
                c = int(len(A) * 0.7)
                pr.append(clf.predict(norm(A[c:], dmin, dmax)))
                ym_.append(ym[c:])
                yi.append(yip[c:])
            chave = "%s_%s" % (PFX[d], PFX[t])
            if t == "kim":
                res[chave] = {"rotulo_ip": mede(pr, yi, ORDEM), "rotulo_mac": mede(pr, ym_, ORDEM)}
                r = res[chave]["rotulo_ip"]
            else:
                res[chave] = r = mede(pr, ym_, ORDEM)
            print("%s->%s: macro-F1 %.4f FP %.4f" % (d, t, r["macro_f1"], r["fp_total"]), flush=True)
    json.dump(res, open(os.path.join(BASE, "matriz_c1.json"), "w"), indent=1)

    # ---------- tabelas ----------
    doms = res["notas"]["dominios"]

    def cel(d, t):
        v = res["%s_%s" % (PFX[d], PFX[t])]
        return v["rotulo_ip"] if t == "kim" else v
    S = [("%s→%s" % (SIGLA[d], SIGLA[t]), cel(d, t)) for d in doms for t in doms]
    L = ["**Tabela XIII (FP em janela benigna, % dos quadros rotulados normais na janela de teste de cada captura)**", "",
         "| captura | " + " | ".join(s for s, _ in S) + " |", "|---|" + "---:|" * len(S)]
    for n in ORDEM:
        L.append("| %s | %s |" % (n, " | ".join("%.3f%%" % (100 * r["fp_por_captura"][n]["fp"]) for _, r in S)))
    L.append("| **todas** | %s |" % " | ".join("%.3f%%" % (100 * r["fp_total"]) for _, r in S))
    L += ["", "**Tabela XIV (F1 por classe e macro-F1)**", "",
          "| classe | " + " | ".join(s for s, _ in S) + " |", "|---|" + "---:|" * len(S)]
    for c in CL:
        L.append("| %s | %s |" % (c, " | ".join("%.4f" % r["f1"][c] for _, r in S)))
    L.append("| **macro-F1** | %s |" % " | ".join("%.4f" % r["macro_f1"] for _, r in S))
    L += ["", "**Recall por classe de ataque**", "", "| classe | " + " | ".join(s for s, _ in S) + " |",
          "|---|" + "---:|" * len(S)]
    for c in CL[1:]:
        L.append("| %s | %s |" % (c, " | ".join("%.4f" % r["recall"][c] for _, r in S)))
    S2 = [("%s→β (MAC)" % SIGLA[d], res["%s_beta" % PFX[d]]["rotulo_mac"]) for d in doms]
    L += ["", "**Variante: β rotulado por MAC (mesmos modelos)**", "", "| | " + " | ".join(s for s, _ in S2) + " |",
          "|---|" + "---:|" * len(S2)]
    for n in ORDEM:
        L.append("| FP %s | %s |" % (n, " | ".join("%.3f%%" % (100 * r["fp_por_captura"][n]["fp"]) for _, r in S2)))
    for c in CL:
        L.append("| F1 %s | %s |" % (c, " | ".join("%.4f" % r["f1"][c] for _, r in S2)))
    L.append("| macro-F1 | %s |" % " | ".join("%.4f" % r["macro_f1"] for _, r in S2))
    for c in CL[1:]:
        L.append("| recall %s | %s |" % (c, " | ".join("%.4f" % r["recall"][c] for _, r in S2)))
    open(os.path.join(BASE, "matriz_c1.md"), "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()

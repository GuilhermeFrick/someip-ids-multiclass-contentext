"""Valida src/kim_faithful.py contra os vetores publicados por Kim et al. (Figshare).

Extrai as 12 features dos 7 PCAPs, normaliza com os limites globais (como o Kim, sobre o
conjunto inteiro) e compara com X_train/X_test.npy:
  - bloco benigno: o .npy intercala pares (treino) e ímpares (teste) do benign_traffic.pcap
    sem o 1º pacote; tem de bater linha a linha;
  - demais blocos: mostra os tamanhos para casar os arquivos de ataque depois.

Uso (na imagem someip-parity:1):
    python3 scripts/kim_validate.py --pcap /d --npy /k --out /work/kimf
"""
import argparse
import os
import sys
import time

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402

FILES = ["benign_traffic.pcap", "dos_noti_flood.pcap", "fuzzy_sd_offer_rand_noti(1).pcap",
         "fuzzy_sd_offer_rand_noti(2).pcap", "fuzzy_sd_offer_rand_noti(3).pcap",
         "mitm_multi_attacker.pcap", "mitm_single_attacker.pcap"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--npy", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    t0 = time.time()
    models = kf.fit_models(os.path.join(a.pcap, FILES[0]))
    print("modelos ajustados %.0f s" % (time.time() - t0), flush=True)
    raw = {}
    for f in FILES:
        cache = os.path.join(a.out, f + ".npz")
        if os.path.exists(cache):
            d = np.load(cache)
            raw[f] = d["X"]
        else:
            X, ts, macs, ips = kf.extract(os.path.join(a.pcap, f), models)
            np.savez(cache, X=X, ts=ts, mac=np.frombuffer(b"".join(macs), np.uint8).reshape(-1, 6),
                     ip=np.frombuffer(b"".join(ips), np.uint8).reshape(-1, 4))
            raw[f] = X
        print("%-36s %9d pacotes  %.0f s" % (f, len(raw[f]), time.time() - t0), flush=True)
    allX = np.concatenate(list(raw.values()))
    lo, hi = allX.min(0), allX.max(0)
    np.savez(os.path.join(a.out, "minmax.npz"), lo=lo, hi=hi)
    Xtr = np.load(os.path.join(a.npy, "X_train.npy"), mmap_mode="r")
    Xte = np.load(os.path.join(a.npy, "X_test.npy"), mmap_mode="r")
    ytr = np.load(os.path.join(a.npy, "y_train.npy"))
    yte = np.load(os.path.join(a.npy, "y_test.npy"))
    print("Kim: treino", Xtr.shape, "teste", Xte.shape, "ataques treino/teste", int(ytr.sum()), int(yte.sum()))
    B = kf.normalize(raw[FILES[0]], lo, hi)
    nb = len(B)
    ktr = np.asarray(Xtr[:(nb + 1) // 2], dtype=np.float64)
    kte = np.asarray(Xte[:nb // 2], dtype=np.float64)
    for nome, ours, kim in (("treino (pares)", B[0::2], ktr), ("teste (ímpares)", B[1::2], kte)):
        d = np.abs(ours - kim)
        print("bloco benigno %-16s max|dif| por coluna:" % nome, " ".join("%.1e" % x for x in d.max(0)))
    # tamanhos dos blocos seguintes, para casar os arquivos de ataque
    trans = np.flatnonzero(np.diff(ytr) != 0) + 1
    print("transições de rótulo no treino:", trans[:10], "...", len(trans))
    print("[ok] %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()

"""Descobre quais pacotes de cada PCAP de ataque o Kim rotulou como ataque.

Casa, como subsequência, as linhas do bloco de ataque do .npy (treino e teste intercalados)
com as linhas normalizadas do arquivo, na ordem do Kim. Depois compara IPs, portas e protocolo
dos pacotes rotulados e não rotulados, lendo o PCAP de novo.
"""
import argparse
import collections
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import kim_faithful as kf  # noqa: E402

ORDEM = ["dos_noti_flood.pcap", "mitm_single_attacker.pcap", "mitm_multi_attacker.pcap",
         "fuzzy_sd_offer_rand_noti(2).pcap", "fuzzy_sd_offer_rand_noti(3).pcap",
         "fuzzy_sd_offer_rand_noti(1).pcap"]
# ordem dos arquivos no bloco de normais do .npy (recuperada por scripts/kim_normal_order.py)
ORDEM_NORMAL = ["fuzzy_sd_offer_rand_noti(2).pcap", "fuzzy_sd_offer_rand_noti(3).pcap",
                "fuzzy_sd_offer_rand_noti(1).pcap", "dos_noti_flood.pcap",
                "mitm_single_attacker.pcap", "mitm_multi_attacker.pcap"]


def meta(pcap):
    """(src, dst, proto, sport, dport) de cada pacote TCP/UDP, sem o 1º, como em extract()."""
    out = []
    first = True
    for _, raw in kf.read_pcap(pcap):
        if kf.views(raw) is None:
            continue
        if first:
            first = False
            continue
        l4o = 14 + (raw[14] & 15) * 4
        out.append((".".join(map(str, raw[26:30])), ".".join(map(str, raw[30:34])), raw[23],
                    int.from_bytes(raw[l4o:l4o + 2], "big"), int.from_bytes(raw[l4o + 2:l4o + 4], "big")))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--npy", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--pcap", required=True)
    a = ap.parse_args()
    mm = np.load(os.path.join(a.out, "minmax.npz"))
    Xtr = np.load(os.path.join(a.npy, "X_train.npy"), mmap_mode="r")
    Xte = np.load(os.path.join(a.npy, "X_test.npy"), mmap_mode="r")
    nb = len(np.load(os.path.join(a.out, "benign_traffic.pcap.npz"))["X"])
    na = 831159
    atk = np.empty((2 * na, 12), np.float32)
    # o split par/ímpar é sobre o array global [benigno | ataque | normal]; o benigno tem nb
    # linhas, então o bloco de ataque começa no índice global nb: ímpar -> 1a linha no teste
    t0, t1 = (Xtr, Xte) if nb % 2 == 0 else (Xte, Xtr)
    atk[0::2] = t0[(nb + 1) // 2 if t0 is Xtr else nb // 2:][:na]
    atk[1::2] = t1[(nb + 1) // 2 if t1 is Xtr else nb // 2:][:na]
    pos = 0
    rot = {}
    for f in ORDEM:
        X = kf.normalize(np.load(os.path.join(a.out, f + ".npz"))["X"], mm["lo"], mm["hi"]).astype(np.float32)
        idx = []
        i = 0
        while pos < len(atk) and i < len(X):
            if np.abs(X[i] - atk[pos]).max() < 2e-6:
                idx.append(i)
                pos += 1
            i += 1
            # o arquivo acabou para o Kim quando a próxima linha dele casa melhor no próximo arquivo
            if len(idx) and i - idx[-1] > 200000:
                break
        idx = np.array(idx, dtype=np.int64)
        rot[f] = idx
        np.save(os.path.join(a.out, f + ".kim_attack_idx.npy"), idx)
        M = meta(os.path.join(a.pcap, f))
        lab = np.zeros(len(X), bool)
        lab[idx] = True
        print("== %s: %d linhas casadas (bloco do Kim até a posição %d)" % (f, len(idx), pos))
        for nome, sel in (("ATAQUE (Kim)", lab), ("normal (Kim)", ~lab)):
            c = collections.Counter((M[k][0], M[k][1], M[k][2]) for k in np.flatnonzero(sel))
            print("   %s: %d pacotes; pares src>dst/proto mais comuns:" % (nome, sel.sum()))
            for (s, d, p), n in c.most_common(8):
                print("        %-15s > %-16s p%-2d %8d" % (s, d, p, n))
    print("total casado", pos, "de", len(atk))


if __name__ == "__main__":
    main()

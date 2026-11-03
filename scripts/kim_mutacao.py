"""Só um sinal muda: o detector treinado no Kim continua achando o tráfego normal?

Reescreve o benign_traffic.pcap trocando APENAS um campo (double LE) de um sinal; tamanhos,
tempos, IDs e todo o resto ficam idênticos. Extrai as features (modelo de bytes ajustado no
benigno ORIGINAL, como no treino), pega os últimos 30% (o teste temporal) e aplica os modelos
salvos por scripts/kim_fluxo.py. Mapa dos sinais: docs/sinais-kim.md.

Perfis:
  original       controle, nada muda
  gps_vel_x1.1   velocidade do GPS (0x1003, patamares de 3 a 22 m/s) multiplicada por 1,1
  gps_vel_+2     velocidade do GPS somada de 2 m/s quando o carro anda
  vde_a_16       campo A do VDE (0x1001; quase sempre 0, com picos) fixo em 16
  vde_a_conducao campo A do VDE seguindo 12 + 8 sen(2πt/120), ruído 0,3

Uso: python3 scripts/kim_mutacao.py --pcap <dir> --out <dir com modelo_fl16.json>
"""
import argparse
import json
import math
import os
import struct
import sys
from multiprocessing import Pool

import numpy as np
import xgboost as xgb

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "src"))
sys.path.insert(0, AQUI)
import kim_faithful as kf  # noqa: E402
from kim_c1_multiclass import c1_extra  # noqa: E402
from kim_multiclass import CLASSES  # noqa: E402

# (último octeto do IP de origem, serviço) -> {evento: deslocamento do double no payload}
CAMPOS = {"vde": (10, 0x1001, {1: 0, 2: 8, 3: 0, 4: 0}),     # campo A do VDE
          "gps": (4, 0x1003, {1: 24, 2: 24, 3: 16})}         # velocidade do GPS
FRAC = 0.7


def novo_valor(perfil, v, t, rng):
    if perfil == "gps_vel_x1.1":
        return v * 1.1
    if perfil == "gps_vel_+2":
        return v + 2.0 if v > 0 else v
    if perfil == "vde_a_16":
        return 16.0
    return max(0.0, 12 + 8 * math.sin(2 * math.pi * t / 120) + rng.normal(0, 0.3))


def muta(src, dst, perfil):
    """Copia o PCAP trocando a velocidade; devolve quantos pacotes mudaram."""
    rng = np.random.default_rng(0)
    n = 0
    t0 = None
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(fi.read(24))
        while True:
            reg = fi.read(16)
            if len(reg) < 16:
                break
            sec, frac, incl, orig = struct.unpack("<IIII", reg)
            raw = bytearray(fi.read(incl))
            ts = sec + frac / 1e6
            t0 = ts if t0 is None else t0
            ip, svc, campo = CAMPOS[perfil.split("_")[0]] if perfil != "original" else (None, None, None)
            if ip is not None and len(raw) > 34 and raw[23] == 6 and raw[29] == ip:
                o = 14 + (raw[14] & 0x0F) * 4
                p = o + (raw[o + 12] >> 4) * 4
                if len(raw) >= p + 16 and int.from_bytes(raw[p:p + 2], "big") == svc:
                    ev = int.from_bytes(raw[p + 2:p + 4], "big")
                    if ev in campo and len(raw) >= p + 16 + campo[ev] + 8:
                        q = p + 16 + campo[ev]
                        v = struct.unpack("<d", raw[q:q + 8])[0]
                        raw[q:q + 8] = struct.pack("<d", novo_valor(perfil, v, ts - t0, rng))
                        n += 1
            fo.write(reg)
            fo.write(raw)
    return n


def roda(args):
    pcap_dir, tmp, perfil = args
    src = os.path.join(pcap_dir, "benign_traffic.pcap")
    dst = os.path.join(tmp, "benign_%s.pcap" % perfil)
    n = muta(src, dst, perfil)
    models = kf.fit_models(src)                     # ajustado no benigno ORIGINAL
    X = kf.extract(dst, models, por_fluxo=True)[0]
    E = c1_extra(dst)
    os.remove(dst)
    return perfil, n, X.astype(np.float32), E


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    perfis = ["original", "gps_vel_x1.1", "gps_vel_+2", "vde_a_16", "vde_a_conducao"]
    with Pool(len(perfis)) as pool:
        dados = pool.map(roda, [(a.pcap, a.out, p) for p in perfis])
    res = {}
    for k, nf in (("fl16", 16), ("fl12", 12)):
        mp = os.path.join(a.out, "modelo_%s.json" % k)
        if not os.path.exists(mp):
            continue
        bst = xgb.Booster(); bst.load_model(mp)
        for perfil, n, X, E in dados:
            M = np.hstack([X, E]) if nf == 16 else X
            M = M[int(FRAC * len(M)):]
            pred = bst.predict(xgb.DMatrix(M)).argmax(1)
            dist = {CLASSES[c]: int((pred == c).sum()) for c in range(5)}
            fp = float((pred != 0).mean())
            res["%s|%s" % (k, perfil)] = {"pacotes_mudados": n, "fp": fp, "predicoes": dist}
            print("%s  %-15s  pacotes mudados %7d   FP no teste %.3f%%   %s" % (k, perfil, n, 100 * fp, dist), flush=True)
    json.dump(res, open(os.path.join(a.out, "kim_mutacao.json"), "w"), indent=1)


if __name__ == "__main__":
    main()

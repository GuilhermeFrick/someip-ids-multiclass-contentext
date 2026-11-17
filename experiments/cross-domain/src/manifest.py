"""Gera feats/manifest.json: Kim (7), mutações (4; a 'original' é o próprio benigno), bancada.

Para acrescentar o domínio gama (CARLA): mais entradas com dom="gama", o PCAP e o mapa de MACs
(MAC -> classe), e rodar extrai.py --so gama/.
"""
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import caminhos as K  # noqa: E402
import json
import os
import sys

BASE = K.WORK
KIMD = K.KIM_DIR
RUNS = K.BANCADA_DIR
MUT = K.MUT_DIR
BEN_IPS = ["172.18.0.%d" % i for i in range(2, 11)]
KIM = [("benign", "benign_traffic.pcap", {}, 0),
       ("dos", "dos_noti_flood.pcap", {"02:42:ac:12:00:0b": 1}, 1),
       ("fuzzy1", "fuzzy_sd_offer_rand_noti(1).pcap", {"02:42:ac:12:00:11": 2}, 2),
       ("fuzzy2", "fuzzy_sd_offer_rand_noti(2).pcap", {"02:42:ac:12:00:0c": 2}, 2),
       ("fuzzy3", "fuzzy_sd_offer_rand_noti(3).pcap", {"02:42:ac:12:00:0c": 2}, 2),
       ("mitm_multi", "mitm_multi_attacker.pcap", {"02:42:ac:12:00:0e": 4, "02:42:ac:12:00:0f": 4}, 4),
       ("mitm_single", "mitm_single_attacker.pcap", {"02:42:ac:12:00:0d": 3}, 3)]
PAPEL = {"dos": 1, "fuzzy": 2, "fuzzy2": 2, "fuzzy3": 2, "mitm_single": 3, "mitm_relay": 4, "mitm_impostor": 4}


def macs_de(path):
    macs = {}
    if os.path.exists(path):
        for linha in open(path):
            p = linha.split()
            if len(p) == 2:
                macs[p[0].lower()] = PAPEL[p[1]]
    return macs


T = []
for nome, f, macs, c in KIM:
    T.append({"name": "kim/" + nome, "dom": "kim", "pcap": os.path.join(KIMD, f), "macs": macs,
              "ip_atk_class": c, "benign_ips": BEN_IPS, "out": os.path.join(BASE, "feats", "kim", nome)})
for m in (["gps_vel_x1.1", "gps_vel_+2", "vde_a_16", "vde_a_conducao"] if MUT else []):
    T.append({"name": "mut/" + m, "dom": "mut", "pcap": os.path.join(MUT, "benign_%s.pcap" % m), "macs": {},
              "out": os.path.join(BASE, "feats", "mut", m)})
for d in (sorted(os.listdir(RUNS)) if RUNS else []):
    pc = os.path.join(RUNS, d, "scn.pcap")
    if not os.path.isdir(os.path.join(RUNS, d)) or not os.path.exists(pc):
        continue
    T.append({"name": "bancada/" + d, "dom": "bancada", "pcap": pc,
              "macs": macs_de(os.path.join(RUNS, d, "injector.mac")),
              "out": os.path.join(BASE, "feats", "bancada", d)})
# domínio gama (CARLA), somente leitura: ~/gama/v1/<captura>/{scn.pcap,injector.mac,scn.labels}
GAMA = K.GAMA_DIR
if os.path.isdir(GAMA):
    for d in sorted(os.listdir(GAMA)):
        pc = os.path.join(GAMA, d, "scn.pcap")
        if os.path.exists(pc):
            T.append({"name": "gama/" + d, "dom": "gama", "pcap": pc,
                      "macs": macs_de(os.path.join(GAMA, d, "injector.mac")),
                      "out": os.path.join(BASE, "feats", "gama", d)})
# domínio parado (γ-parado), mesma estrutura do gama; só as 16 colunas da C1 ("c1": True)
PARADO = K.PARADO_DIR
if os.path.isdir(PARADO):
    for d in sorted(os.listdir(PARADO)):
        pc = os.path.join(PARADO, d, "scn.pcap")
        if os.path.exists(pc):
            T.append({"name": "parado/" + d, "dom": "parado", "pcap": pc, "c1": True,
                      "macs": macs_de(os.path.join(PARADO, d, "injector.mac")),
                      "out": os.path.join(BASE, "feats", "parado", d)})
os.makedirs(os.path.join(BASE, "feats"), exist_ok=True)
json.dump(T, open(os.path.join(BASE, "feats", "manifest.json"), "w"), indent=1)
print(len(T), "tarefas", file=sys.stderr)

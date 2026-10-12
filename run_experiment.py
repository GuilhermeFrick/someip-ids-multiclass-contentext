#!/usr/bin/env python3
"""Runner headless do experimento multiclasse canônico (promovido do nb07 para src/pipeline.py).

Uso:
    python run_experiment.py --pcap-dir data/pcap --out results --device cpu
    python run_experiment.py --max-packets 20000 --no-figs      # smoke test rápido

Reproduz results/metrics_temporal.json (números/figuras da Tabela VII) sem GPU.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
import pipeline  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="data/pcap")
    ap.add_argument("--out", default="results")
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    ap.add_argument("--n-jobs", type=int, default=-1)
    ap.add_argument("--no-figs", action="store_true")
    ap.add_argument("--max-packets", type=int, default=None,
                    help="limita pacotes por arquivo (smoke test)")
    a = ap.parse_args()

    out = pipeline.run(a.pcap_dir, a.out, device=a.device, n_jobs=a.n_jobs,
                       make_figs=not a.no_figs, max_packets=a.max_packets)
    print(json.dumps({
        "macro_f1_16": round(out["model_16feat"]["macro_f1"], 4),
        "macro_f1_12": round(out["ablation_12feat"]["macro_f1"], 4),
        "accuracy": round(out["model_16feat"]["accuracy"], 4),
        "ext_us_per_pkt": round(out["timing"]["extraction_us_per_pkt"], 2),
        "inf_us_per_pkt": round(out["timing"]["inference_us_per_pkt"], 2),
    }, indent=2))


if __name__ == "__main__":
    main()

"""Baixa os PCAPs crus do dataset SOME/IP do Kim (figshare) para data/pcap/.

Fonte pública: https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450
Os PCAPs (~1,9 GB) NÃO são versionados no git — este script os obtém da fonte original,
permitindo rodar o extrator de features desde o tráfego cru.

Uso: python scripts/download_pcaps.py
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request

ARTICLE = "30970450"
API = f"https://api.figshare.com/v2/articles/{ARTICLE}"
OUT = os.path.join(os.path.dirname(__file__), "..", "data", "pcap")


def md5(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def download(url: str, dest: str) -> None:
    with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            f.write(b)
            done += len(b)
            if total:
                print(f"\r    {done/1e6:6.0f} / {total/1e6:.0f} MB", end="")
    print()


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    print(f"consultando figshare (artigo {ARTICLE})...")
    meta = json.loads(urllib.request.urlopen(API).read())
    files = [f for f in meta["files"] if f["name"].lower().endswith(".pcap")]
    print(f"{len(files)} PCAPs disponíveis.\n")
    for f in files:
        dest = os.path.join(OUT, f["name"])
        want_md5 = f.get("supplied_md5") or f.get("computed_md5")
        if os.path.exists(dest) and os.path.getsize(dest) == f["size"]:
            if not want_md5 or md5(dest) == want_md5:
                print(f"[ok] {f['name']} já presente")
                continue
        print(f"[baixando] {f['name']} ({f['size']/1e6:.0f} MB)")
        download(f["download_url"], dest)
        if want_md5:
            print(f"    md5: {'OK' if md5(dest) == want_md5 else 'FALHOU'}")
    print(f"\nPCAPs em {os.path.abspath(OUT)}")
    print("Próximo: python src/extract_ext.py --pcap-dir data/pcap --out data/ours_ext")


if __name__ == "__main__":
    main()

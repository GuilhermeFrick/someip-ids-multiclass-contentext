#!/usr/bin/env bash
# Descomprime o dataset γ-parado (guardado comprimido no Git LFS) para o formato que os scripts leem.
# Uso, a partir da raiz do repositório:   git lfs pull && bash data/parado/prepara.sh
set -euo pipefail
cd "$(dirname "$0")/v1"
for f in */*.gz; do
    alvo="${f%.gz}"
    if [ -s "$alvo" ]; then
        continue
    fi
    echo "  $alvo"
    gunzip -k "$f"
done
sha256sum -c ../SHA256SUMS

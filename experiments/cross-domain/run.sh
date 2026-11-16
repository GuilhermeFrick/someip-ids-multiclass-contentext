#!/usr/bin/env bash
# Matriz entre domínios do C1 publicado: β→β, β→γ, γ→γ e γ→β (Tabelas XIII e XIV do artigo).
#
# Pré-requisitos (ver README.md):
#   - PCAPs do Kim em data/pcap/          (python scripts/download_pcaps.py)
#   - γ descomprimido em data/gama/v1/    (git lfs pull && bash data/gama/prepara.sh)
#   - ambiente Python da C1               (pip install -r requirements.txt)
#
# Uso, a partir da raiz do repositório:
#     JOBS=3 bash experiments/cross-domain/run.sh
# JOBS = extrações em paralelo; cada uma ocupa até ~2 GB de RAM.
set -euo pipefail
cd "$(dirname "$0")"
PY="${PY:-python3}"
JOBS="${JOBS:-3}"
WORK="${WORK_DIR:-$PWD/work}"
mkdir -p "$WORK/logs"

echo "[1/7] manifesto das capturas"
$PY src/manifest.py
echo "[2/7] extração das features (Kim e γ) com o modelo de bytes publicado"
$PY src/extrai.py --manifest "$WORK/feats/manifest.json" --jobs "$JOBS" > "$WORK/logs/extrai.log" 2>&1
echo "[3/7] modelo de bytes de γ (70% iniciais do benigno) e colunas correspondentes"
$PY src/bm_gama.py --manifest "$WORK/feats/manifest.json" --jobs "$JOBS" > "$WORK/logs/bm_gama.log" 2>&1
echo "[4/7] reprodução do artefato publicado (macro-F1 0,9689)"
$PY src/checa_model16.py
echo "[5/7] paridade da extração de γ com o FeatureStreamer de referência"
$PY src/verifica_gama.py 200000 mitm_multi fuzzy2 dos
echo "[6/7] matriz entre domínios"
$PY src/matriz_c1.py
echo "[7/7] origem do falso positivo"
$PY src/matriz_fp_origem.py
echo "saídas: $WORK/matriz_c1.json, $WORK/matriz_c1.md, $WORK/results/"

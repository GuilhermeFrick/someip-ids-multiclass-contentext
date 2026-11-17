#!/usr/bin/env bash
# Matriz entre domínios, β→β, β→γ, γ→γ e γ→β, para os dois detectores:
#   - C1 publicado (multiclasse, 16 features): Tabelas XIII e XIV do artigo;
#   - baseline de Kim (binário, 12 features, extrator fiel src/kim_faithful.py).
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

echo "[1/8] manifesto das capturas"
$PY src/manifest.py
echo "[2/8] extração das features (Kim e γ) com o modelo de bytes publicado"
$PY src/extrai.py --manifest "$WORK/feats/manifest.json" --jobs "$JOBS" > "$WORK/logs/extrai.log" 2>&1
echo "[3/8] modelo de bytes de γ (70% iniciais do benigno) e colunas correspondentes"
$PY src/bm_gama.py --manifest "$WORK/feats/manifest.json" --jobs "$JOBS" --so kim/,gama/,parado/ > "$WORK/logs/bm_gama.log" 2>&1
if [ -d "${PARADO_DIR:-$(cd ../.. && pwd)/data/parado/v1}" ]; then   # γ-parado, se existir
    $PY src/bm_gama.py --manifest "$WORK/feats/manifest.json" --jobs "$JOBS" --dom parado --so kim/,gama/,parado/         > "$WORK/logs/bm_parado.log" 2>&1
fi
echo "[4/8] reprodução do artefato publicado (macro-F1 0,9689)"
$PY src/checa_model16.py
echo "[5/8] paridade da extração de γ com o FeatureStreamer de referência"
$PY src/verifica_gama.py 200000 mitm_multi fuzzy2 dos
echo "[6/8] matriz entre domínios"
$PY src/matriz_c1.py
echo "[7/8] origem do falso positivo"
$PY src/matriz_fp_origem.py
echo "[8/8] matriz entre domínios do baseline binário de Kim"
$PY src/matriz_kim.py --jobs "$JOBS" > "$WORK/logs/kim.log" 2>&1
echo "saídas: $WORK/matriz_c1.{json,md}, $WORK/matriz_kim.{json,md}, $WORK/results/"

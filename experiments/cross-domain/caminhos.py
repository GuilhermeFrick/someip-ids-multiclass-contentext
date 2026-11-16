"""Caminhos da avaliação entre domínios (β = dataset do Kim, γ = dataset gerado com o CARLA).

Todos os scripts de src/ importam daqui. O padrão assume este repositório inteiro, com os PCAPs
do Kim em data/pcap/ (scripts/download_pcaps.py) e o γ em data/gama/v1/ (Git LFS, descomprimido
por data/gama/prepara.sh). Cada caminho pode ser trocado por variável de ambiente.
"""
import os

EXP = os.path.dirname(os.path.abspath(__file__))                       # experiments/cross-domain
REPO = os.environ.get("C1_REPO", os.path.dirname(os.path.dirname(EXP)))  # raiz do repositório
KIM_DIR = os.environ.get("KIM_DIR", os.path.join(REPO, "data", "pcap"))
GAMA_DIR = os.environ.get("GAMA_DIR", os.path.join(REPO, "data", "gama", "v1"))
WORK = os.environ.get("WORK_DIR", os.path.join(EXP, "work"))           # features, modelos, saídas
# Opcionais, usados só na exploração de features (não na matriz): o domínio "bancada" (viagens
# sintéticas da bancada) e as mutações de sinal do benigno do Kim. Vazios = ignorados.
BANCADA_DIR = os.environ.get("BANCADA_DIR", "")
MUT_DIR = os.environ.get("MUT_DIR", "")

C1_SRC = os.path.join(REPO, "src")          # extrator e pipeline publicados da C1
# Artefatos PUBLICADOS do C1, versionados com md5 conferido (artefatos-treino/README.md):
# model_16.json (25 rodadas, profundidade 8), bytemodels.npz e minmax.npy.
C1_ART = os.environ.get("C1_ART", os.path.join(REPO, "artefatos-treino"))
C1_RESULTS = os.path.join(REPO, "results")  # saída de execução do C1; features.npz, se existir
LIB = os.path.join(EXP, "lib")              # streamers da bancada (someip-testbench/experiments/bench-train)
ARTEFATOS = os.path.join(EXP, "artefatos")
FEATS = os.path.join(WORK, "feats")
SAIDA = os.path.join(WORK, "results")

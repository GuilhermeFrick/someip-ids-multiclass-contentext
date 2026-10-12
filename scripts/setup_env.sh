#!/usr/bin/env bash
# Prepara o ambiente Python do repo (venv + deps). Idempotente:
# verifica se tudo já está instalado na versão certa e, se estiver, NÃO reinstala.
set -euo pipefail
cd "$(dirname "$0")/.."          # raiz do repo
VENV=.venv
REQ=requirements.txt

env_ok() {
  # retorna 0 (OK) se o venv existe e importa tudo com o xgboost na versão fixada
  [ -x "$VENV/bin/python" ] || return 1
  "$VENV/bin/python" - <<'PY' >/dev/null 2>&1
import importlib, xgboost
assert xgboost.__version__ == "3.3.0", xgboost.__version__
for m in ("numpy", "scapy", "sklearn", "matplotlib"):
    importlib.import_module(m)
PY
}

if env_ok; then
  echo "==> ambiente já OK — nada a instalar"
else
  echo "==> instalando ambiente (venv + deps de $REQ)"
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$VENV/bin/pip" install --upgrade pip
  "$VENV/bin/pip" install -r "$REQ"     # pip pula o que já está satisfeito
fi

"$VENV/bin/python" -c "import numpy,scapy,xgboost,sklearn,matplotlib;print('numpy',numpy.__version__,'| xgboost',xgboost.__version__,'| sklearn',sklearn.__version__,'| scapy',scapy.__version__)"

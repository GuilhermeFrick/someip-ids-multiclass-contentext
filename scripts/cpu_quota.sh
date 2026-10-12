#!/usr/bin/env bash
# Reproduz a Tabela 5 do Kim: 1 núcleo (core pinning) + varredura de cota de CPU.
# Para cada cota, roda latency_run.py sob systemd-run (AllowedCPUs + CPUQuota) e
# coleta o JSON de latência por estágio. Resultado: results/latency_quota.json.
#
# Requisitos: systemd (Ubuntu), sudo, artefatos já salvos em $ART (run_experiment.py).
# Uso:   bash scripts/cpu_quota.sh
#        ART=results PCAP=data/pcap/benign_traffic.pcap N=1000 bash scripts/cpu_quota.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PY=./.venv/bin/python
ART=${ART:-results}
PCAP=${PCAP:-data/pcap/benign_traffic.pcap}
N=${N:-1000}
OUT=${OUT:-results/latency_quota.json}

# cotas (%) como no Kim: 1 núcleo de 5% a 100%, depois 2/4/8 núcleos (200/400/800%).
QUOTAS="5 10 15 20 25 30 35 40 45 50 55 60 70 75 80 85 90 95 100 200 400 800"
# cota -> conjunto de núcleos permitidos (AllowedCPUs); default 1 núcleo (core 0).
declare -A CPUS=( [200]="0-1" [400]="0-3" [800]="0-7" )

echo "[" > "$OUT.tmp"; first=1
for q in $QUOTAS; do
  allowed=${CPUS[$q]:-0}
  echo ">> cota ${q}%  (AllowedCPUs=${allowed})"
  res=$(sudo systemd-run --scope -q \
          -p "AllowedCPUs=${allowed}" -p "CPUQuota=${q}%" \
          $PY latency_run.py --artifacts "$ART" --pcap "$PCAP" --n "$N" 2>/dev/null)
  [ "$first" -eq 1 ] || echo "," >> "$OUT.tmp"; first=0
  printf '{"cpu_quota_pct": %s, "allowed_cpus": "%s", "latency": %s}' "$q" "$allowed" "$res" >> "$OUT.tmp"
done
echo "" >> "$OUT.tmp"; echo "]" >> "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "salvo: $OUT"

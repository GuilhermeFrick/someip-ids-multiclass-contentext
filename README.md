# SOME/IP IDS Multiclasse — features `content_ext`

IDS multiclasse para SOME/IP com **16 features** de conteúdo e comportamento
(**12 do baseline + 4 propostas**, **sem identificadores de cabeçalho**), em 5 classes
(`normal, dos, fuzzy, mitm_single, mitm_multi`). Split temporal (honesto): **macro-F1 0,964**.

Os PCAPs crus (~1,9 GB, dados públicos do Kim) **não** são versionados — um script os baixa
do figshare, permitindo rodar tudo **desde o tráfego cru**.

## Estrutura
```
.
├── notebooks/
│   ├── experimento.ipynb      # RELATÓRIO (comece aqui): 12 -> diagnóstico -> 16 -> comparação
│   └── build_experimento.py   #   gerador do notebook
├── src/                       # motor PCAP -> features (também usado pelo runner headless)
│   ├── someip.py              #   parser SOME/IP / SD
│   ├── bytemodel.py           #   modelo de bytes posicional (loglik, entropia, Hamming)
│   ├── labeler.py             #   constantes de classe + rótulo por nó atacante
│   ├── extract.py             #   12 features do baseline + fit dos byte-models
│   ├── extract_ext.py         #   FeatureStreamer: 12 + 4 propostas = 16 features
│   ├── pipeline.py            #   extração + split temporal + treino + métricas (headless)
│   └── latency.py             #   harness de latência por estágio (por pacote)
├── run_experiment.py          # roda o pipeline headless -> results/
├── latency_run.py             # mede latência carregando artefatos salvos
├── scripts/
│   ├── download_pcaps.py      #   baixa os PCAPs do figshare -> data/pcap/
│   ├── setup_env.sh           #   venv + deps (idempotente)
│   └── cpu_quota.sh           #   varredura de cota de CPU (1 núcleo, estilo Kim)
├── data/ours_ext/             # features pré-extraídas (Git LFS) — legado
├── docs/relatorio-validacao-split.md
├── legacy/                    # fora do escopo do artigo (avaliação de PCAP do simulador)
└── requirements.txt
```

## Como rodar

### Notebook (recomendado) — relatório ponta a ponta
Abra **`notebooks/experimento.ipynb`** (roda local, na VM ou no Colab). Ele cobre:
ambiente → dados → extração → **detecção com 12 features** → **diagnóstico** (onde falha) →
**detecção com 16 features** (12 + 4 propostas) → **comparação** (ganho e custo de latência).

### Headless (linha de comando)
```bash
bash scripts/setup_env.sh                 # venv + deps (xgboost==3.3.0)
python scripts/download_pcaps.py          # ~1,9 GB do figshare -> data/pcap/
python run_experiment.py --device cpu     # extração + treino + métricas -> results/
```

## As 16 features
- **12 do baseline** (conteúdo/timing): intervalo IP, log-verossimilhança e entropia cruzada
  (SOME/IP, SD, TCP/UDP), distância de Hamming, Δ de tamanho (IP e TCP/UDP).
- **4 propostas** (comportamentais): `repeat_rate` (*payload repetition*),
  `someip_len` + `l4_len` (*absolute size*), `src_payload_div` (*source diversity*).

## Resultado (split temporal por arquivo, 70/30)
As 12 features puras do baseline, no multiclasse, deixam dois gargalos (`fuzzy` e `mitm_multi`).
As 4 features propostas os resolvem, a **custo de latência de extração praticamente nulo**:

| Conjunto de features | macro-F1 | fuzzy | mitm_multi |
|---|---:|---:|---:|
| 12 (baseline) | 0,779 | 0,545 | 0,577 |
| **16 (12 + 4 propostas)** | **0,964** | **0,999** | **0,838** |

Justificativa do split (vazamento temporal) em
[`docs/relatorio-validacao-split.md`](docs/relatorio-validacao-split.md).

## Fonte do dataset
T. Kim et al. *SOME/IP traffic (normal and abnormal).* figshare, 2026.
https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

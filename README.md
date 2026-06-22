# SOME/IP IDS Multiclasse — features `content_ext`

Repositório **autossuficiente** para reproduzir o IDS multiclasse SOME/IP com as features
**`content_ext`** (12 do Kim + 4 comportamentais, **sem cabeçalho**) em 5 classes
(`normal, dos, fuzzy, mitm_single, mitm_multi`). Desempenho in-scope honesto (split temporal):
**macro-F1 0,966** — ver a tabela de regimes em [Resultado](#resultado).

Inclui os **extratores de features**, o **dataset de features já extraídas** e o **experimento**.
Os PCAPs crus (~1,9 GB, dados públicos do Kim) **não** são versionados — um script os baixa da
fonte original (figshare), permitindo rodar tudo **desde o tráfego cru**.

## Estrutura
```
.
├── src/                       # extratores de features (PCAP -> features)
│   ├── someip.py              #   parser SOME/IP / SD
│   ├── bytemodel.py           #   modelo de bytes posicional (log-likelihood, entropia, Hamming)
│   ├── labeler.py             #   rótulo por nó atacante
│   ├── extract.py             #   12 features do Kim
│   └── extract_ext.py         #   + 4 comportamentais (content_ext) -> 21 features
├── scripts/download_pcaps.py  # baixa os PCAPs do figshare -> data/pcap/
├── data/ours_ext/             # features JÁ extraídas (X.npz, y_multi.npz) via Git LFS
├── docs/relatorio-validacao-split.md  # vazamento temporal, split correto, robustez a params
├── notebooks/                 # ver tabela abaixo
├── multiclass_content_ext.py  # script: experimento (split aleatório)
├── split_comparison.py        # script: aleatório vs temporal
├── kim_params_experiment.py   # script: params do Kim nos dois splits
└── README.md
```

## Notebooks

| Notebook | Split | Para quê |
|---|---|---|
| **`00-pipeline-completo.ipynb`** ⭐ | **temporal** | Pipeline ponta a ponta **correto** (download→extração→split temporal→treino→métricas). **Comece por aqui.** |
| `02-comparacao-splits.ipynb` | ambos | Compara aleatório vs temporal por arquivo (auditoria do vazamento). |
| `03-params-kim-gpu.ipynb` | ambos | Roda com os **hiperparâmetros do Kim** em **GPU**; métricas + matriz de confusão + ROC/PR. |
| `05-ids-multiclasse-content-ext.ipynb` | aleatório | Comparação **Kim-12 vs content_ext** (número absoluto **otimista** — ilustrativo). |

> O número **honesto** in-scope é o do split **temporal** (`00`/`02`): **macro-F1 0,966**.
> O `05` usa split aleatório (0,9936) — válido só como comparação relativa de *features*.

## Como rodar

### Opção A — direto das features (rápido, sem baixar PCAPs)
As features já vêm no repo (`data/ours_ext/`, via Git LFS):
```bash
pip install numpy scikit-learn xgboost matplotlib
# RECOMENDADO: pipeline correto (split temporal) — abra notebooks/00-pipeline-completo.ipynb
python split_comparison.py                # aleatório vs temporal (número honesto)
python multiclass_content_ext.py          # experimento com split aleatório (otimista)
```

### Opção B — desde o tráfego cru (reproduz a extração)
```bash
pip install numpy scapy xgboost scikit-learn matplotlib
python scripts/download_pcaps.py                              # ~1,9 GB do figshare -> data/pcap/
python src/extract_ext.py --pcap-dir data/pcap --out data/ours_ext   # PCAP -> 21 features
python multiclass_content_ext.py                             # experimento
```

## As features
- **12 do Kim** (conteúdo/timing): intervalo IP, log-verossimilhança e entropia cruzada
  (SOME/IP, SD, TCP/UDP), Hamming, Δ de tamanho.
- **+4 comportamentais** (`content_ext`): `repeat_rate`, `someip_len`, `l4_len`, `src_payload_div`.
- Índices `content_ext` em `X.npz` (21 colunas): `[0..11] + [12,13,14,16]`.

## Resultado
Com `content_ext` (sem cabeçalho), os gargalos `fuzzy`/`mitm_multi` das 12 features puras do Kim
(0,50/0,57) sobem para 0,998/0,989. O desempenho depende do protocolo de avaliação:

| Regime | macro-F1 |
|---|---:|
| Split aleatório (otimista, só ilustrativo) | 0,9936 |
| **Split temporal por arquivo (honesto, in-scope)** | **0,9658** |
| Zero-day / *leave-one-attack-out* (ataque novo) | ~0,60 |

Detalhes e justificativa do split em [`docs/relatorio-validacao-split.md`](docs/relatorio-validacao-split.md).

## Validação do split (vazamento temporal)
Tráfego é sequencial → um split **aleatório** infla as métricas (pacotes da mesma rajada em
treino e teste). Comparação honesta (`split_comparison.py` / `notebooks/02-comparacao-splits.ipynb`):

| Split | macro-F1 |
|---|---:|
| Aleatório 70/30 (otimista) | 0,9936 |
| **Temporal por arquivo** 70/30 (honesto) | **0,9658** |
| Zero-day / leave-one-attack-out (ataque novo) | ~0,60 |

A queda existe mas é **modesta** (−2,8 pts): o modelo mantém **0,966 > 0,95** mesmo sem vazamento.
A única classe que cai forte é `mitm_multi` (0,989→0,848, a do *relay*). O limite real de
generalização é o **zero-day (~0,60)**, reportado no `someip-ids-benchmark`.
**Para a dissertação:** reportar o **temporal** como in-scope honesto e o **zero-day** como
generalização; o aleatório fica só como ilustração do viés.

## Fonte do dataset
T. Kim et al. *SOME/IP traffic (normal and abnormal).* figshare, 2026.
https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

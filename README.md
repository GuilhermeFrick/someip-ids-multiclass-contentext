# SOME/IP IDS Multiclasse — features `content_ext`

Repositório **autossuficiente** para reproduzir o IDS multiclasse SOME/IP com as features
**`content_ext`** (12 do Kim + 4 comportamentais, **sem cabeçalho**) — **macro-F1 ≈ 0,99** em
5 classes (`normal, dos, fuzzy, mitm_single, mitm_multi`).

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
├── notebooks/05-ids-multiclasse-content-ext.ipynb   # experimento (executado)
├── multiclass_content_ext.py  # versão script do experimento
└── README.md
```

## Como rodar

### Opção A — direto das features (rápido, sem baixar PCAPs)
As features já vêm no repo (`data/ours_ext/`, via Git LFS):
```bash
pip install numpy scikit-learn xgboost matplotlib
python multiclass_content_ext.py          # treina + métricas + matriz + curvas
# ou abra notebooks/05-ids-multiclasse-content-ext.ipynb
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
macro-F1 **0,9936** · accuracy **0,9987** · ROC-AUC ≈ 1,0 — os gargalos `fuzzy`/`mitm_multi`
(0,50/0,57 com as 12 puras) sobem para 0,998/0,989, **sem features de cabeçalho** (evitando o
overfitting que elas causam).

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

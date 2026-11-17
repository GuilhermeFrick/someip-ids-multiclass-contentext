# Avaliação entre domínios: o baseline de Kim e o C1 em três datasets

Mede se um detector de intrusão treinado em um dataset SOME/IP generaliza para tráfego de outra
origem, e **por que** não generaliza. Há **três datasets** e **dois modelos**. Cada modelo é
treinado em cada dataset e testado em todos: 2 modelos × 3 × 3 = 18 avaliações.

**Datasets**

| Sigla | Dataset | Gerador do tráfego | Conteúdo das mensagens |
|---|---|---|---|
| β | Kim *et al.*, figshare (detalhes em [Dados](#dados)) | rede de 9 ECUs do autor | veículo praticamente parado |
| γ-parado | gerado pela bancada, `data/parado/v1/` | a nossa bancada (a mesma do γ) | os valores do benigno de β (veículo parado) |
| γ | gerado pela bancada com o CARLA, `data/gama/v1/` | a nossa bancada | veículo andando pela cidade |

O γ-parado é um **experimento de controle**: β → γ-parado muda só o gerador, e γ-parado → γ muda
só o conteúdo. Assim dá para separar o efeito da bancada do efeito da dinâmica do veículo.

**Modelos**

| Modelo | Saída | *Features* | Classificador | Script |
|---|---|---|---|---|
| **Kim (baseline)** | binária: normal × ataque | as 12 de Kim, pelo extrator fiel `src/kim_faithful.py` (recuperado dos vetores publicados pelos autores) | XGBoost, 1.000 árvores, profundidade 6, `eta` 0,05, *subsample* e *colsample* 0,8; limiar 0,36 (os do artigo de Kim) | `src/matriz_kim.py` |
| **C1** (este trabalho) | 5 classes: normal, DoS, *Fuzzy*, MITM single, MITM multi | 16: as 12 de Kim na implementação da C1 + 4 novas (`src/extract_ext.py`) | XGBoost, 25 rodadas, profundidade 8, `eta` 0,3 (artefato publicado `model_16.json`) | `src/matriz_c1.py` |

O C1 produz as Tabelas XIII (falso positivo em janela benigna) e XIV (F1 por classe) da Seção VI.E
do artigo. O baseline de Kim responde se a falta de generalização já existe no estado da arte ou
foi introduzida pelas *features* novas da C1.

## Dados

| | Dataset | Onde | Como obter |
|---|---|---|---|
| **β** | Kim *et al.*, *SOME/IP traffic (Benign and Attack samples)*, figshare, DOI 10.6084/m9.figshare.30970450 (CC BY 4.0). 7 PCAPs, ~25 min cada | `data/pcap/` | `python scripts/download_pcaps.py` (confere o md5 de cada arquivo); SHA-256 em `data/SHA256SUMS-kim` |
| **γ** | Bancada `someip-testbench` com o CARLA 0.9.15: mesma matriz de comunicação e mesmos ataques de β, conteúdo de um veículo conduzido no simulador. 7 capturas de 1.500 s | `data/gama/v1/` | `git lfs pull && bash data/gama/prepara.sh`; descrição em `data/gama/v1/README.md` |
| **γ-parado** | A mesma bancada, com os *payloads* do benigno de β no lugar do CARLA. 7 capturas de 1.500 s | `data/parado/v1/` | `git lfs pull && bash data/parado/prepara.sh`; descrição em `data/parado/v1/README.md` |

As sete capturas de cada dataset correspondem uma a uma: `benign`, `dos`, `fuzzy1`, `fuzzy2`,
`fuzzy3`, `mitm_single` e `mitm_multi`.

## Protocolo

**Detector C1.** Exatamente como publicado: `src/extract_ext.py` (`FeatureStreamer`) e os artefatos
versionados em `artefatos-treino/` (md5 no README da pasta):

| Artefato | Conteúdo |
|---|---|
| `model_16.json` | XGBoost, 25 rodadas × 5 classes = 125 árvores, profundidade máxima 8, `eta` 0,3, `tree_method=hist`, `max_bin` 256, `multi:softprob` |
| `bytemodels.npz` | modelo de *bytes* (log-probabilidade posicional, suavização de Laplace) ajustado no benigno de β |
| `minmax.npy` | normalização min-max das 16 *features*, ajustada em β |

**Split.** Temporal, por captura: os 70% iniciais de cada captura (em ordem de chegada) são treino
e os 30% finais são teste (`pipeline.temporal_split`). **Todo teste é feito nos 30% finais de cada
captura do dataset de destino**, para que todas as células sejam comparáveis.

**Treino em cada dataset** (treino → teste):

| Treino | Modelo de *bytes* | Normalização | Classificador |
|---|---|---|---|
| β | publicado | publicada | `model_16.json` publicado |
| γ | ajustado nos 70% iniciais do benigno de γ (`feats/bm-gama.npz`) | ajustada no treino de γ | XGBoost com os hiperparâmetros acima, nos 70% iniciais de cada captura |
| γ-parado | ajustado nos 70% iniciais do benigno de γ-parado (`feats/bm-parado.npz`) | ajustada no treino de γ-parado | idem |

No dataset de destino, **nada é reajustado**: as *features* são recalculadas com o modelo de *bytes*
do dataset de treino e normalizadas com o min-max do treino.

**Normalização em precisão dupla.** As *features* do modelo publicado são normalizadas com o min-max
publicado em precisão dupla e só então convertidas para float32 (`.Xk.npy`, escrito por
`extrai.py`), exatamente como em `results/features.npz`. Isso importa: normalizar a partir das
*features* já em float32 muda o último dígito de algumas colunas, e o modelo publicado tem cortes
exatamente sobre esses valores (ver [Verificações](#verificações)).

**Rótulos.** β: regra do pipeline publicado, por IP de origem (fora das 9 ECUs = ataque). γ e
γ-parado: por MAC do atacante (`scn.labels`). As duas regras só divergem no MITM multi, em que o
atacante forja o IP da VDE nos `StopOffer`: o rótulo por IP os marca como normais; o rótulo por
MAC, como ataque. A matriz também reporta β com rótulo por MAC.

**Métricas.**
- *Falso positivo em janela benigna*, por captura: fração dos quadros rotulados normais na janela
  de teste da captura que o modelo classifica como qualquer classe de ataque.
- F1 por classe, macro-F1 e *recall* por classe de ataque, sobre a janela de teste das 7 capturas.

**Protocolo do baseline de Kim** (`src/matriz_kim.py`). O mesmo *split* e a mesma regra de não
reajustar nada no dataset de destino:
- o modelo de *bytes* das três visões (L4, SOME/IP, SD) é ajustado nos 70% iniciais da captura
  benigna do dataset de treino; as *features* de todos os datasets são recalculadas com ele; a
  normalização min-max vem do conjunto de treino;
- rótulo de β: o do próprio Kim (`artefatos/kim_attack_idx.npz`, os índices dos pacotes que ele
  rotulou como ataque, recuperados dos vetores publicados por `scripts/kim_label_rule.py`), usado no
  treino; também reportado com o rótulo por MAC. Rótulo de γ e γ-parado: por MAC;
- métricas binárias: ROC-AUC e PR-AUC (sem limiar) e, no limiar 0,36, F1, precisão e *recall* da
  classe ataque, falso positivo total e por captura, e *recall* por captura de ataque.

## Como rodar

A partir da raiz do repositório, com o ambiente da C1 (`pip install -r requirements.txt`):

```bash
python scripts/download_pcaps.py                   # β em data/pcap/
git lfs pull && bash data/gama/prepara.sh          # γ em data/gama/v1/
bash data/parado/prepara.sh                        # γ-parado em data/parado/v1/ (opcional)
JOBS=3 bash experiments/cross-domain/run.sh        # ~1 h com 3 extrações em paralelo (até ~2 GB de RAM cada)
```

Sem o γ-parado, as matrizes ficam 2 × 2 (β e γ). O `run.sh` executa, em ordem:
1. o manifesto das capturas (o γ-parado entra só com as 16 colunas da C1);
2. a extração das *features* com o modelo de *bytes* publicado (e as `.Xk.npy`);
3. os modelos de *bytes* de γ e de γ-parado e as colunas correspondentes nos três datasets;
4. a conferência do artefato publicado;
5. a paridade da extração de γ com o `FeatureStreamer` de referência;
6. a matriz do C1;
7. a origem do falso positivo;
8. a matriz do baseline de Kim: para cada dataset de treino, a extração com o extrator fiel
   (~15 s por captura) e um treino de 1.000 árvores (~3 min com 8 *threads*).

As saídas ficam em `experiments/cross-domain/work/` (fora do Git). Os caminhos estão em
`caminhos.py` e podem ser trocados por variável de ambiente (`KIM_DIR`, `GAMA_DIR`, `PARADO_DIR`,
`WORK_DIR`, `C1_ART`, `XK_WORK`).

## Resultados de referência

Rodadas de 17/11/2026, na VM `someip-bench` (8 vCPU, 15 GB). Arquivos completos em `resultados/`
(`matriz_c1.json` e `matriz_kim.json` trazem todas as métricas, matrizes de confusão e contagens;
os `.md` trazem as tabelas completas, inclusive o falso positivo por captura). **Rodada única**: os
modelos publicados e treinos determinísticos, sem variação de semente.

### C1 (multiclasse)

**Falso positivo na captura benigna** (linha = treino, coluna = teste)

| Treino ↓ / Teste → | β | γ-parado | γ |
|---|---:|---:|---:|
| β | 0,033% | 0,575% | 17,895% |
| γ-parado | 0,882% | 0,055% | 15,980% |
| γ | 1,692% | 1,800% | 0,273% |

**Falso positivo em todas as capturas**

| Treino ↓ / Teste → | β | γ-parado | γ |
|---|---:|---:|---:|
| β | 1,068% | 1,617% | 11,744% |
| γ-parado | 2,404% | 0,083% | 8,932% |
| γ | 3,525% | 1,852% | 0,927% |

**Macro-F1**

| Treino ↓ / Teste → | β | γ-parado | γ |
|---|---:|---:|---:|
| β | 0,9689 | 0,9085 | 0,6158 |
| γ-parado | 0,8372 | 0,9930 | 0,6007 |
| γ | 0,7021 | 0,8613 | 0,9511 |

**F1 por classe nas quatro células da Tabela XIV do artigo**

| Classe | β → β | β → γ | γ → γ | γ → β |
|---|---:|---:|---:|---:|
| normal | 0,9945 | 0,9244 | 0,9906 | 0,9600 |
| DoS | 0,9981 | 0,9556 | 0,9862 | 0,8955 |
| *Fuzzy* | 0,9991 | 0,4329 | 0,9643 | 0,7196 |
| MITM single | 0,9947 | 0,4075 | 0,9812 | 0,4137 |
| MITM multi | 0,8580 | 0,3586 | 0,8332 | 0,5216 |
| **macro-F1** | **0,9689** | **0,6158** | **0,9511** | **0,7021** |

Com β rotulado por MAC (mesmos modelos): β → β tem macro-F1 0,9427 (MITM multi com F1 0,7335 e
*recall* 0,7104), γ → β tem 0,6863 e γ-parado → β, 0,8558.

### Baseline de Kim (binário)

Semente do artigo de Kim (42). β com o rótulo do Kim; γ e γ-parado pelo MAC.

**Falso positivo na captura benigna**

| Treino ↓ / Teste → | β | γ-parado | γ |
|---|---:|---:|---:|
| β | 1,50% | 0,99% | 14,53% |
| γ-parado | 4,52% | 1,38% | 17,68% |
| γ | 15,73% | 14,42% | 4,22% |

**PR-AUC** (qualidade da separação normal × ataque, sem limiar)

| Treino ↓ / Teste → | β | γ-parado | γ |
|---|---:|---:|---:|
| β | 0,919 | 0,653 | 0,475 |
| γ-parado | 0,749 | 0,871 | 0,459 |
| γ | 0,776 | 0,713 | 0,844 |

O β → β reproduz o experimento de *split* temporal de `scripts/kim_experiments.py` (exp2b: ROC-AUC
0,9839, F1 0,8156); aqui, ROC-AUC 0,9837 e F1 0,8153.

### Leitura

1. **A bancada reproduz o gerador de β.** Trocando só o gerador (β → γ-parado), os dois modelos
   quase não dão alarme falso na captura benigna (C1: 0,58%; Kim: 0,99%). Ressalva: é o melhor
   caso, porque o γ-parado publica os valores do próprio β, que o modelo viu no treino.
2. **A dinâmica do veículo, sozinha, derruba os dois modelos.** Trocando só o conteúdo (γ-parado →
   γ), o falso positivo na benigna vai a 16,0% (C1) e 17,7% (Kim), a mesma ordem de β → γ (17,9% e
   14,5%). A falta de generalização vem do conteúdo das mensagens.
3. **O problema já existe no baseline.** O detector de Kim também falha fora do domínio; não foi a
   C1 que o criou.
4. **Assimetria.** O C1 treinado em γ funciona razoavelmente em γ-parado (1,8% na benigna), mas o
   treinado em γ-parado falha em γ (16,0%): no γ o carro fica parado de 30% a 45% do tempo, então
   quem treina com o carro andando também vê o carro parado; o contrário não.
5. **Diferença residual da bancada.** Nas capturas de DoS e MITM single, o modelo de Kim treinado
   em β dá de 7% a 10% de falso positivo nos dois datasets gerados, independentemente do conteúdo:
   na bancada, as ECUs que perdem o serviço reconectam mais rápido (~9 por segundo, contra ~6,5 em
   β).

## Verificações

- **Reprodução:** o β → β dá macro-F1 0,9689 e o F1 por classe publicado, idênticos ao artigo.
- **Normalização:** as `.Xk.npy` do DoS de β, extraídas do PCAP, são idênticas bit a bit às
  colunas correspondentes de `results/features.npz`. Normalizando a partir do float32, em vez
  disso, 22.607 pacotes do teste do DoS (4%) mudam de classe e o β → β cai para 0,9426. Por isso o
  β → γ informado antes (0,5909, calculado a partir do float32) passou a **0,6158**; só o DoS muda
  (F1 de 0,8337 para 0,9556), e o falso positivo não muda.
- **Paridade da extração:** nos 200 mil primeiros pacotes de `mitm_multi`, `fuzzy2` e `dos` de γ,
  as 16 *features* de `extrai.py` são idênticas, bit a bit, às do `FeatureStreamer` de referência
  (scapy `RawPcapReader`, `extract_ext.py`).
- **Rótulo:** o rótulo por MAC recalculado a partir de `injector.mac` coincide com `scn.labels`
  quadro a quadro nas 7 capturas de γ e nas 7 de γ-parado.
- **Segmentação TCP:** nas 14 capturas de β e γ, todo segmento TCP com *payload* carrega exatamente
  uma mensagem SOME/IP completa; a leitura segmento a segmento do extrator é suficiente.
- **Determinismo:** a matriz de Kim 3 × 3 reproduziu exatamente as quatro células da rodada 2 × 2
  anterior.

## Ressalvas

- **Assimetria de ajuste, herdada do publicado:** em β, o modelo de *bytes* e a normalização foram
  ajustados incluindo a janela de teste; em γ e γ-parado, só nos 70% iniciais. O β → β tem uma
  vantagem pequena que os outros não têm.
- **Rodada única,** sem estimativa de variância.
- **Fragilidade do modelo publicado:** o resultado depende do último dígito do float32 de algumas
  *features* (ver [Verificações](#verificações)).
- **Rótulo de β no baseline de Kim:** a regra do próprio Kim não coincide com o MAC do atacante
  (marca a mais no DoS, no *Fuzzy* 2 e no MITM single, e a menos no MITM multi: 338.496 contra
  590.680 pacotes). Com β rotulado pelo MAC, o β → β do baseline tem ROC-AUC 0,8676 e F1 0,7115.
- **Origem do falso positivo** (`resultados/matriz_fp_origem.json`):
  - No β → γ, 70% dos quadros da VDE no benigno de γ são classificados como ataque. O conteúdo de
    um veículo em movimento é, para o modelo de *bytes* de β, conteúdo incomum no serviço 0x1001,
    que no treino só aparecia nos ataques.
  - O FP de 6,6% na captura `mitm_multi` do β → β vem da vítima, a ADAS, cujo tráfego muda durante
    o ataque.
- **Os streamers em `lib/`** (Service Discovery, comportamento, eco) são cópias de
  `someip-testbench/experiments/bench-train/`. Entram na extração porque `extrai.py` gera também as
  *features* da exploração, mas **não** participam das matrizes, que usam só as 16 colunas
  publicadas.

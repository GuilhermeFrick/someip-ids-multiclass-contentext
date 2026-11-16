# Avaliação entre domínios do C1 (β ↔ γ)

Mede se o detector C1 publicado (XGBoost multiclasse, 16 *features* por pacote, sem identificadores
de cabeçalho) generaliza para tráfego de outra origem. Produz as Tabelas XIII (falso positivo em
janela benigna) e XIV (F1 por classe) da Seção VI.E do artigo.

## Dados

| | Dataset | Onde | Como obter |
|---|---|---|---|
| **β** | Kim *et al.*, *SOME/IP traffic (normal and abnormal)*, figshare, DOI 10.6084/m9.figshare.30970450 (CC BY 4.0). 7 PCAPs, ~25 min cada | `data/pcap/` | `python scripts/download_pcaps.py` (confere o md5 de cada arquivo); SHA-256 em `data/SHA256SUMS-kim` |
| **γ** | Gerado pela bancada `someip-testbench` com o CARLA 0.9.15: mesma matriz de comunicação e mesmos ataques de β, conteúdo de um veículo conduzido no simulador. 7 capturas de 1.500 s | `data/gama/v1/` | `git lfs pull && bash data/gama/prepara.sh`; descrição completa em `data/gama/v1/README.md` |

As sete capturas de cada dataset correspondem uma a uma: `benign`, `dos`, `fuzzy1`, `fuzzy2`,
`fuzzy3`, `mitm_single` e `mitm_multi`.

## Protocolo

**Detector.** O C1 exatamente como publicado: `src/extract_ext.py` (`FeatureStreamer`) e os
artefatos versionados em `artefatos-treino/` (md5 no README da pasta):

| Artefato | Conteúdo |
|---|---|
| `model_16.json` | XGBoost, 25 rodadas × 5 classes = 125 árvores, profundidade máxima 8, `eta` 0,3, `tree_method=hist`, `max_bin` 256, `multi:softprob` |
| `bytemodels.npz` | modelo de *bytes* (log-probabilidade posicional, suavização de Laplace) ajustado no benigno de β |
| `minmax.npy` | normalização min-max das 16 *features*, ajustada em β |

**Split.** Temporal, por captura: os 70% iniciais de cada captura (em ordem de chegada) são treino
e os 30% finais são teste (`pipeline.temporal_split`). **Todo teste é feito nos 30% finais de cada
captura do domínio de destino**, para que as quatro colunas sejam comparáveis.

**Cenários** (treino → teste):

| Cenário | Modelo de *bytes* | Normalização | Classificador |
|---|---|---|---|
| β → β | publicado (β) | publicada (β) | `model_16.json` publicado |
| β → γ | publicado (β), **sem reajuste** | publicada (β), **sem reajuste** | `model_16.json`, **sem reajuste** |
| γ → γ | ajustado no benigno de γ, só nos 70% iniciais | ajustada no treino de γ | o mesmo procedimento: XGBoost com os hiperparâmetros acima, treinado nos 70% iniciais de cada captura de γ |
| γ → β | o de γ, sem reajuste | a de γ, sem reajuste | o modelo do γ → γ, sem reajuste |

**Rótulos.** β: regra do pipeline publicado, por IP de origem (fora das 9 ECUs = ataque). γ: por
MAC do atacante (`scn.labels`, gerado pela bancada). As duas regras só divergem no MITM multi, em
que o atacante forja o IP da VDE nos `StopOffer`. O rótulo por IP os marca como normais; o rótulo
por MAC, como ataque. A matriz também reporta β com rótulo por MAC.

**Métricas.**
- *Falso positivo em janela benigna*, por captura: fração dos quadros rotulados normais na janela
  de teste da captura que o modelo classifica como qualquer classe de ataque.
- F1 por classe, macro-F1 e *recall* por classe de ataque, sobre a janela de teste das 7 capturas.

## Como rodar

A partir da raiz do repositório, com o ambiente da C1 (`pip install -r requirements.txt`):

```bash
python scripts/download_pcaps.py               # β em data/pcap/
git lfs pull && bash data/gama/prepara.sh      # γ em data/gama/v1/
JOBS=3 bash experiments/cross-domain/run.sh    # ~1 h com 3 extrações em paralelo (até ~2 GB de RAM cada)
```

O `run.sh` executa, em ordem:
1. o manifesto das capturas;
2. a extração das *features* (β e γ) com o modelo de *bytes* publicado;
3. o modelo de *bytes* de γ;
4. a conferência do artefato publicado;
5. a paridade da extração de γ com o `FeatureStreamer` de referência;
6. a matriz;
7. a origem do falso positivo.

As saídas ficam em `experiments/cross-domain/work/` (fora do Git). Os caminhos estão em
`caminhos.py` e podem ser trocados por variável de ambiente (`KIM_DIR`, `GAMA_DIR`, `WORK_DIR`,
`C1_ART`).

## Resultados de referência

Rodada de 15/11/2026, na VM `someip-bench` (8 vCPU, 15 GB). Arquivos completos em `resultados/`
(`matriz_c1.json` traz todas as métricas, matrizes de confusão e contagens). **Rodada única**:
o modelo publicado e um treino determinístico em γ, sem variação de semente.

**Falso positivo em janela benigna**

| Captura | β → β | β → γ | γ → γ | γ → β |
|---|---:|---:|---:|---:|
| benign | 0,033% | 17,895% | 0,273% | 1,692% |
| dos | 0,007% | 1,848% | 0,015% | 0,989% |
| fuzzy1 | 0,024% | 20,546% | 0,640% | 1,738% |
| fuzzy2 | 0,028% | 3,203% | 0,061% | 1,568% |
| fuzzy3 | 0,013% | 1,809% | 0,031% | 1,438% |
| mitm_single | 0,014% | 1,922% | 0,063% | 5,464% |
| mitm_multi | 6,635% | 25,176% | 4,996% | 10,795% |
| todas | 1,068% | 11,744% | 0,927% | 3,525% |

**F1 por classe (recall entre parênteses)**

| Classe | β → β | β → γ | γ → γ | γ → β |
|---|---:|---:|---:|---:|
| normal | 0,9945 | 0,9220 | 0,9906 | 0,9600 |
| DoS | 0,9981 (0,9994) | 0,8337 (0,7798) | 0,9862 (0,9948) | 0,8955 (0,9509) |
| *Fuzzy* | 0,9991 (0,9991) | 0,4328 (0,5620) | 0,9643 (0,9547) | 0,7196 (0,5677) |
| MITM single | 0,9947 (0,9999) | 0,4074 (0,8814) | 0,9812 (0,9827) | 0,4137 (0,4627) |
| MITM multi | 0,8580 (0,9880) | 0,3584 (0,2759) | 0,8332 (0,8343) | 0,5216 (0,5218) |
| **macro-F1** | **0,9689** | **0,5909** | **0,9511** | **0,7021** |

Com β rotulado por MAC (mesmos modelos): β → β tem macro-F1 0,9427 (MITM multi com F1 0,7335 e
*recall* 0,7104) e γ → β tem 0,6863.

## Verificações

- **Reprodução:** o β → β dá macro-F1 0,9689 e o F1 por classe publicado, idênticos ao artigo.
- **Paridade da extração:** nos 200 mil primeiros pacotes de `mitm_multi`, `fuzzy2` e `dos` de γ,
  as 16 *features* de `extrai.py` são idênticas, bit a bit, às do `FeatureStreamer` de referência
  (scapy `RawPcapReader`, `extract_ext.py`).
- **Rótulo:** o rótulo por MAC recalculado a partir de `injector.mac` coincide com `scn.labels`
  quadro a quadro nas 7 capturas de γ.
- **Segmentação TCP:** nas 14 capturas (β e γ), todo segmento TCP com *payload* carrega exatamente
  uma mensagem SOME/IP completa; a leitura segmento a segmento do extrator é suficiente.

## Ressalvas

- **Assimetria de ajuste, herdada do publicado:** em β, o modelo de *bytes* e a normalização foram
  ajustados incluindo a janela de teste; em γ, só nos 70% iniciais. O β → β tem uma vantagem
  pequena que o γ → γ não tem.
- **Rodada única,** sem estimativa de variância.
- **Origem do falso positivo** (`resultados/matriz_fp_origem.json`):
  - No β → γ, 70% dos quadros da VDE no benigno de γ são classificados como ataque. O conteúdo de
    um veículo em movimento é, para o modelo de *bytes* de β, conteúdo incomum no serviço 0x1001,
    que no treino só aparecia nos ataques.
  - O FP de 6,6% na captura `mitm_multi` do β → β vem da vítima, a ADAS, cujo tráfego muda durante
    o ataque.
- **Os streamers em `lib/`** (Service Discovery, comportamento, eco) são cópias de
  `someip-testbench/experiments/bench-train/`. Entram na extração porque `extrai.py` gera também as
  *features* da exploração, mas **não** participam da matriz do C1, que usa só as 16 colunas
  publicadas.

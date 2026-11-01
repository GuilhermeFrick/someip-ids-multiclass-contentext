# Artefatos do treino

Os três arquivos que o sensor em C++ carrega. **Estão versionados de propósito**, contra a regra
geral de `results/` ficar no `.gitignore`, por um motivo concreto: em 01/11/2026 eles existiam
**apenas** na VM de treino, que estava desligada. Religá-la foi a única forma de recuperá-los.

`results/` é saída de execução e se apaga sem prejuízo porque roda de novo. Estes não: regerar o
`model_16.json` exige uma rodada de treino inteira.

| arquivo | o que é | md5 |
|---|---|---|
| `model_16.json` | modelo XGBoost adotado: 125 árvores (25 rodadas × 5 classes), 16 features, `multi:softprob` | `c894f126cfc51fb97067c4633a87853c` |
| `bytemodels.npz` | tabelas posicionais de log-probabilidade, `someip (64,256)`, `sd (80,256)`, `l4 (64,256)` | `5bad3dfa3512bc3e243103974d5de151` |
| `minmax.npy` | limites de normalização, duas linhas de 16 | `73be054d2c43e212af9f8433304a39ea` |

`content_idx.json` e `metrics_temporal.json` também estavam na VM, e são **byte a byte iguais** aos
que já estão em [`results-publicados/`](../results-publicados/). Não foram duplicados aqui.

## ⚠️ As datas não são da mesma rodada

| arquivo | data na VM |
|---|---|
| `minmax.npy`, `bytemodels.npz` | 12/10 23:13 |
| `model_16.json` | **15/10 23:26** |

Isso foi **verificado, não assumido**. Os limites e as tabelas de bytes dependem só dos PCAPs e do
código de extração, não dos hiperparâmetros do modelo, então os dois foram recalculados do zero e
comparados:

- `minmax.npy`: **idêntico bit a bit** a um recálculo em float64 a partir dos 7 PCAPs;
- `bytemodels.npz`: `sd` idêntico bit a bit, `someip` e `l4` dentro de **1,8e-15** (~1 ULP de
  float64, ruído de ordem de acumulação entre versões de `numpy`);
- `model_16.json`: os dois motores em C++ reproduzem o `predict` do XGBoost em 2048 linhas reais do
  dataset, dentro de **2,4e-07**, com a classe escolhida batendo em todas.

Detalhe em `someip-testbench/docs/ARTEFATOS.md`.

## ⚠️ Leia o modelo com xgboost 3.3.0 ou mais novo

O `model_16.json` foi salvo pelo **xgboost 3.3.0**. Lido com o 2.1.3, ele carrega **sem erro
nenhum** e devolve `base_score = 0,5` em vez do vetor por classe que está no arquivo:

```
no arquivo       [2,7467, -1,0028, -0,3698, -0,7514, -0,6227]
lido pelo 2.1.3  [0,5, 0,5, 0,5, 0,5, 0,5]
```

Como o `base_score` aqui é um **vetor**, ele **não cancela no softmax**. Quem ler com uma versão
antiga obtém probabilidades erradas sem nenhum sinal de que algo deu errado.

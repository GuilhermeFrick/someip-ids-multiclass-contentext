# Seleção de hiperparâmetros e ablação de features

Os dois experimentos que sustentam afirmações do artigo. Ficam neste repositório,
e não no da bancada, porque é aqui que o artigo precisa ser reproduzível.

| Script | Sustenta no artigo |
|---|---|
| `select_hyperparams.py` | "os hiperparâmetros foram escolhidos por varredura sobre um conjunto de validação" |
| `ablate_features.py` | a atribuição da separação do *Fuzzy* à feature de diversidade por origem |
| `loo.py` | a contribuição individual de cada uma das quatro features propostas |

Ambos usam o cache `results/features.npz`. A extração **não depende dos
hiperparâmetros**, então roda uma vez só; trocar de modelo exige retreinar, não
reextrair.

---

## 1. Seleção de hiperparâmetros

```bash
python select_hyperparams.py          # -> results/selecao_hiperparametros.json
```

### O método

Split aninhado, preservando a ordem temporal dentro de cada arquivo de captura:

```
|<--------------- treino (70%) --------------->|<---- teste (30%) ---->|
|<-- treino interno (49%) -->|<-- val (21%) -->|
                                                 ^
                                  o teste nunca é tocado na escolha
```

A ordem temporal importa porque o tráfego tem deriva: o teste é um período
posterior. Um split aleatório deixaria o modelo ver o futuro e esconderia o
sobreajuste.

Grade: estimadores ∈ {25, 50, 100, 200, 300} × profundidade ∈ {4, 6, 8},
**15 configurações**. Três etapas: varrer no treino interno avaliando na
validação, escolher pela validação, retreinar a vencedora no treino completo e
só então avaliar no teste.

### O resultado

Escolhida: **25 estimadores, profundidade 8** (125 árvores), macro-F1 de
validação **0,9576**. No teste, **0,9689**, contra **0,9640** da configuração
anterior (300 estimadores, profundidade 8), com 6,7x menos nós.

### Por que não selecionar pelo teste

Uma varredura anterior comparava as configurações pelo macro-F1 de **teste** — o
mesmo conjunto sobre o qual o artigo reporta. A configuração que ela elegia
(50 estimadores, profundidade 4) tinha:

| | valor | posição |
|---|---:|---|
| macro-F1 de **teste** | 0,9695 | **1º de 15** |
| macro-F1 de **validação** | 0,9418 | **7º de 15** |

Vantagem concentrada justamente no conjunto de reporte. Selecionando pelo teste
não há como distinguir isso de mérito real.

### Anomalia conhecida

As configurações de **profundidade 6** degradam acentuadamente a partir de 50
estimadores (macro-F1 de validação cai para ~0,80–0,85, e no teste para 0,5744,
idêntico em 100, 200 e 300 estimadores). O comportamento é determinístico e
reprodutível, mas **não investigado**: nenhuma configuração candidata está nessa
faixa. Os dados estão em `results/selecao_hiperparametros.json`.

---

## 2. Ablação de features

```bash
python ablate_features.py             # -> results/ablacao_features.json
```

### Por que ablação, e não importância

O `gain` do XGBoost é agregado sobre as cinco classes, então uma feature
decisiva para duas classes minoritárias aparece com ganho baixo. A ablação
responde a pergunta certa: *o que acontece com cada classe sem esta feature?*

### O resultado

| subconjunto | nf | macro-F1 | fuzzy | mitm-multi | dos | extração |
|---|---:|---:|---:|---:|---:|---:|
| **all16** | 16 | **0,9689** | **0,9991** | **0,8580** | **0,9981** | 21,91 µs |
| sem `source diversity` | 15 | 0,7795 | **0,5445** | 0,5771 | 0,8586 | 12,77 µs |
| sem as de menor ganho | 13 | 0,8917 | 0,9881 | 0,7841 | **0,7913** | 21,31 µs |
| base12 + repetição | 13 | 0,7788 | 0,5444 | 0,5769 | 0,8589 | 12,66 µs |
| base12 | 12 | 0,7794 | 0,5441 | 0,5767 | 0,8586 | 12,11 µs |
| `lean` | 12 | 0,6387 | 0,5380 | 0,5741 | 0,3667 | 12,18 µs |

O `lean` remove as de menor ganho **e** a `source diversity` ao mesmo tempo, e é a
única configuração em que o DoS também desaba (0,3667). Serve de controle: os dois
efeitos abaixo são independentes e se somam.

Duas conclusões:

1. **A separação do Fuzzy vem da `source diversity`, não da repetição de
   payload.** O subconjunto `base12 + repetição`, que **tem** a feature de
   repetição, dá Fuzzy 0,543 — igual ao baseline sem ela.
2. **Nenhuma feature é removível.** As de menor ganho (intervalo de tempo e
   variação de comprimento) carregam o DoS: sem elas ele cai de 0,998 para 0,791.

### Sobre o custo reportado

A coluna de custo de extração é estimada a partir da decomposição medida por
categoria. Uma categoria só é cobrada se ao menos uma de suas features estiver
presente: remover uma feature de uma categoria de três não economiza nada,
porque o cálculo da categoria continua sendo feito.

É o que explica `no_lowgain` custar 21,31 µs, quase o mesmo que as 16 completas:
ele tira três features, mas nenhuma categoria inteira.

---

## 3. Leave-one-out das features propostas

```bash
python loo.py                         # -> results/leave_one_out.json
```

### A pergunta que a ablação por subconjunto não responde

A ablação compara conjuntos montados, e isso mistura efeitos: `base12` tira as
quatro features propostas de uma vez. O leave-one-out pergunta outra coisa: **com
todas as outras quinze presentes**, quanto custa remover cada proposta isoladamente?

### O resultado

| removida | nf | macro-F1 | Δ | fuzzy | mitm-multi |
|---|---:|---:|---:|---:|---:|
| nenhuma (all16) | 16 | **0,9689** | | 0,9991 | 0,8580 |
| `payload repetition` | 15 | 0,9651 | −0,0038 | 0,9979 | 0,8408 |
| `absolute size` | 14 | 0,9646 | −0,0043 | 0,9980 | 0,8388 |
| `source diversity` | 15 | 0,7795 | **−0,1894** | 0,5445 | 0,5771 |

A `source diversity` responde por praticamente todo o ganho: remover só ela custa
0,19 de macro-F1, contra 0,004 de cada uma das outras duas, uma diferença de mais
de vinte vezes. E as outras duas atuam em outro lugar: o que elas perdem está
concentrado no MITM-multi (0,858 para 0,841 e 0,839), não no Fuzzy, que se mantém
acima de 0,997 sem elas.

`absolute size` são duas features (índices 13 e 14), por isso `nf=14`.

### Consistência com a ablação

A configuração "sem `source diversity`" é a mesma que o `no_srcdiv` da ablação. Os
dois scripts, rodados separadamente, dão **0,779456** nos dois, igual até o último
dígito, e o `all16` também coincide exatamente. O pipeline é determinístico, e os
dois experimentos se checam mutuamente.

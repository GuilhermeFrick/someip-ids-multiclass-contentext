# Relatório — Validação do split (vazamento temporal)

> **Nota de terminologia:** o problema aqui é **vazamento de dados** (*data leakage*) **temporal**,
> **não** vazamento de memória. São coisas diferentes: *data leakage* é informação do conjunto de
> teste "vazar" para o treino, inflando as métricas.

## 1. O problema — vazamento de dados temporal

Tráfego de rede é **inerentemente sequencial**: pacotes consecutivos pertencem à mesma sessão
SOME/IP, ao mesmo fluxo TCP/UDP ou à mesma **rajada de ataque**. Pacotes próximos no tempo são,
portanto, **fortemente correlacionados** (quase idênticos numa inundação de DoS, por exemplo).

Quando se separa treino/teste **embaralhando aleatoriamente** os pacotes, pacotes da **mesma
rajada** caem **dos dois lados** — treino e teste. O modelo então "vê" um pacote da rajada no
treino e é avaliado em outro pacote **milissegundos depois** no teste. Resultado: a métrica fica
**otimista**, porque parte do acerto é "reconhecer um vizinho quase idêntico", não generalização.
É o *data leakage* temporal, um viés clássico (e frequentemente apontado por bancas/revisores) na
avaliação de IDS de rede.

## 2. O split incorreto (versão original)

A primeira versão do experimento usou o split aleatório padrão do scikit-learn:

```python
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.30, random_state=0, stratify=y)
```

Isso **embaralha todas as ~14,2 milhões de linhas** e sorteia 70/30. Estratifica por classe (bom
para o balanceamento), mas **ignora a ordem temporal** — exatamente o que causa o vazamento
descrito acima. O número que sai daí (**macro-F1 0,9936**) é, portanto, **enviesado para cima**.

## 3. A correção — split temporal **por arquivo**

### 3.1 A base: a ordem das linhas do `X`
O extrator (`extract_ext.py`) processa os **7 PCAPs numa ordem fixa** e **concatena** as features
**pacote a pacote**; dentro de cada arquivo, os pacotes ficam **em ordem de captura (temporal)**.
Logo, o **índice da linha** no `X` codifica (a) de qual arquivo é e (b) a posição temporal dentro
do arquivo. Fronteiras (somas acumuladas das contagens da extração):

| linhas | arquivo |
|---|---|
| 0 .. 2.193.801 | benign_traffic |
| 2.193.802 .. 4.058.331 | dos_noti_flood |
| 4.058.332 .. 6.255.444 | fuzzy(1) |
| 6.255.445 .. 7.559.598 | fuzzy(2) |
| 7.559.599 .. 9.783.248 | fuzzy(3) |
| 9.783.249 .. 12.195.777 | mitm_multi |
| 12.195.778 .. 14.233.353 | mitm_single |

### 3.2 A regra do split
Para **cada bloco de arquivo** `[início, fim)`:

```
corte  = início + 0,70 × (qtde de pacotes do arquivo)
treino ← linhas [início, corte)   # primeiros 70%  (cronologicamente mais cedo)
teste  ← linhas [corte,  fim)     # últimos 30%    (cronologicamente mais tarde)
```

Depois, concatenam-se os treinos de todos os arquivos e os testes de todos os arquivos:

```python
tr, te, start = [], [], 0
for _, cnt in FILE_COUNTS:                 # contagem de pacotes por PCAP
    cut = start + int(cnt * 0.7)
    tr.append(np.arange(start, cut))       # 70% iniciais  -> treino
    te.append(np.arange(cut, start + cnt)) # 30% finais    -> teste
    start += cnt
itr, ite = np.concatenate(tr), np.concatenate(te)
```

### 3.3 Por que **por arquivo** (e não de outro jeito)

| Abordagem | O que acontece |
|---|---|
| **Aleatório** (original) | embaralha tudo → pacote e seu vizinho da mesma rajada em treino **e** teste → **vazamento** |
| **Temporal global** (ordenar tudo por tempo e cortar 70%) | benign (1º arquivo) iria todo para treino e mitm (último) todo para teste → **classes separadas por arquivo**, avaliação inválida |
| **Temporal por arquivo** ✅ | dentro de cada arquivo o teste vem **depois** do treino (sem vazamento de continuidade) **e** todos os arquivos contribuem para treino e teste → **todas as classes presentes nos dois lados** |

### 3.4 Verificação
Confirmou-se que o conjunto de teste temporal **contém todas as classes** (senão o macro-F1 seria
inválido):

```
teste temporal — classes: normal 3.780.722 · dos 99.940 · fuzzy 170.209 ·
                          mitm_single 94.360 · mitm_multi 124.777
```

O atacante fica ativo ao longo da captura, então o corte temporal pega rajada nos dois lados — mas
**pacotes diferentes**, sem o vizinho imediato vazando.

## 4. Resultados

| Split | macro-F1 | accuracy |
|---|---:|---:|
| Aleatório 70/30 (otimista) | **0,9936** | 0,9987 |
| **Temporal por arquivo** 70/30 (honesto) | **0,9658** | 0,9890 |
| Zero-day / *leave-one-attack-out* (ataque **novo**) | ~0,60 | — |

F1 por classe (temporal): normal 0,9938 · dos 0,9979 · fuzzy 0,9979 · mitm_single 0,9916 ·
**mitm_multi 0,8477**.

### Natureza da queda do `mitm_multi`: precisão, não detecção

A matriz de confusão (split temporal) mostra que o `mitm_multi` **não é um problema de detecção,
mas de falso alarme**:

| Classe | Precision | Recall | F1 |
|---|---:|---:|---:|
| normal | 0,9999 | 0,9879 | 0,9939 |
| dos | 0,9969 | 0,9994 | 0,9982 |
| fuzzy | 0,9940 | 0,9996 | 0,9968 |
| mitm_single | 0,9881 | 1,0000 | 0,9940 |
| **mitm_multi** | **0,7400** | **0,9937** | 0,8483 |
| macro avg | 0,9438 | **0,9961** | 0,9662 |

O `mitm_multi` tem **recall 0,99** (quase nenhum ataque relay escapa) mas **precisão 0,74**: na
CM, **1,2% do `normal`** é rotulado como `mitm_multi`. Como `normal` domina (~3,78M no teste),
esse 1,2% ≈ **45k falsos positivos** contra ~124k mitm_multi reais → precisão ~0,74.

**Por que faz sentido:** o MitM *relay* **republica notificações legítimas**, então seu tráfego é
por construção *parecido com o normal* — é a fronteira mais borrada. As demais classes têm
assinatura comportamental nítida (≥ 0,99). Em IDS automotivo, **recall alto é o critério-chave**
(não perder ataque); o macro recall de **0,9961** mostra que o detector praticamente não deixa
ataque passar, e o custo concentrado no relay é falso alarme — mitigável por pós-filtro/correlação.

## 4b. Robustez aos hiperparâmetros (parâmetros do Kim)

Para descartar a hipótese de que o resultado vem de um config "agressivo" (e responder a
revisores que pediram mais regularização), re-rodamos o mesmo `content_ext` multiclasse com os
**hiperparâmetros exatos do Kim** (Tabela 2 do artigo): 1000 árvores, `lr=0,05`, `max_depth=6`,
`subsample=0,8`, `colsample=0,8`, `L2=1,0` — muito mais regularizados que os nossos
(300 árvores, `lr=0,3`, `depth=8`, sem subsampling).

| Split | params do Kim | nossos params | Δ |
|---|---:|---:|---:|
| Aleatório 70/30 | 0,9937 | 0,9936 | +0,0001 |
| **Temporal por arquivo** | **0,9675** | 0,9658 | +0,0017 |

**Conclusão:** o desempenho é **robusto à escolha de hiperparâmetros**. Os params *mais
regularizados* do Kim **não reduzem** a métrica — sobem levemente no temporal. Isso refuta a
hipótese de *overfitting por sobre-parametrização*: o sinal está nas **features/dados**, não no
config do modelo. A **única alavanca relevante continua sendo o split** (aleatório 0,99 vs
temporal 0,97, Δ ~2,8 pts ≫ Kim-vs-nosso, Δ ~0,1 pt). Reproduzir: `kim_params_experiment.py`
ou `notebooks/03-params-kim-gpu.ipynb` (GPU).

## 5. Conclusão

- **O vazamento existe** e era real: o split aleatório inflava o resultado em **~2,8 pontos**.
- **Mas a queda é modesta, não um colapso:** sob o split temporal (sem vazamento) o modelo mantém
  **macro-F1 0,966 > 0,95** — nível de produção. A única classe que cai forte é **mitm_multi**
  (0,989 → 0,848), a do *relay*, mais dependente de estrutura de sessão; dos/fuzzy quase não caem
  (assinatura estável no tempo).
- **O limite real de generalização** continua sendo o **zero-day (~0,60)** — ataque de um tipo
  nunca visto — já reportado em `someip-ids-benchmark`.
- **Recomendação:** reportar o **temporal** como número *in-scope* honesto e o **zero-day** como
  generalização; o aleatório fica apenas como **ilustração do viés**.

Reproduzir: `python split_comparison.py` ou `notebooks/02-comparacao-splits.ipynb`.

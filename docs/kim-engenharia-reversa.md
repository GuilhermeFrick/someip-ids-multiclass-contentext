# Engenharia reversa do extrator de Kim et al. (2026)

Kim et al. (Systems 2026, 14, 196) publicaram no Figshare os PCAPs e os vetores de features já
extraídos (`X_train.npy`, `X_test.npy`, `y_*.npy`), mas não o código. O artigo descreve as
fórmulas (Eq. 1 a 7) e omite detalhes que mudam o valor das features. Este documento registra
como o extrator foi recuperado a partir dos próprios vetores e o que ele faz de fato. A
implementação fiel está em [`src/kim_faithful.py`](../src/kim_faithful.py).

## Resultado

| conferência | resultado |
|---|---|
| total de linhas | 14.233.347, igual ao do Kim |
| bloco benigno (2.193.801 linhas), 12 colunas normalizadas | idêntico linha a linha (resíduo ≤ 3,3e-7, precisão do float32) |
| rótulos (1.662.318 ataques) | idênticos |
| `X_train` e `X_test` completos, reconstruídos dos PCAPs | 99,93% das linhas idênticas; 4.981 + 4.977 linhas (0,07%) diferem, todas nos PCAPs de ataque, sobretudo nas colunas do payload TCP/UDP, provavelmente por remontagem de segmentos TCP |

Scripts: `scripts/kim_validate.py` (extrai e confere o bloco benigno),
`scripts/kim_label_rule.py` (recupera os pacotes rotulados como ataque),
`scripts/kim_normal_order.py` e `scripts/kim_rebuild.py` (remontam e conferem os arrays).

## Como o extrator do Kim funciona

**Pacotes.** Todos os quadros IPv4 com TCP ou UDP, em ordem de captura. O primeiro pacote de
cada PCAP é descartado.

**"Pacote anterior" é sempre o anterior da captura inteira**, não o do mesmo fluxo. O artigo
afirma o contrário ("restricted to packets that share the same source and destination IP
addresses and transport-layer ports", p. 16).

| col. | feature | definição |
|---|---|---|
| 0 / 1 | logL / entropia TCP/UDP | visão = payload de transporte (inclui o cabeçalho SOME/IP) |
| 2 / 4 | logL / entropia SOME/IP | visão = o que vem depois dos 16 bytes do cabeçalho SOME/IP; **SD entra junto** |
| 3 / 5 | logL / entropia SD | visão = **array de opções da mensagem SD, com o campo de comprimento**; Find e SubscribeAck, sem opções, viram zeros |
| 6 | Hamming SD | sobre a visão SD |
| 7 | variação do tamanho IP | campo Total Length, contra o pacote anterior |
| 8 | variação do comprimento UDP | só quando o pacote atual e o anterior são UDP; senão, sentinela −9999 |
| 9 | intervalo de tempo | contra o pacote anterior |
| 10 | Hamming TCP/UDP | sobre o payload de transporte |
| 11 | Hamming SOME/IP | sobre a visão SOME/IP |

**Modelo de bytes (cols. 0 a 5).** É ajustado com a visão de **todos** os pacotes do
`benign_traffic.pcap` (menos o primeiro), inclusive os que não têm payload. Cada visão é
**completada com zeros, ou truncada, até L = 64 bytes**, com Laplace α = 1. O escore soma as
64 posições do vetor completado, e a entropia é −logL/64; por isso, normalizadas, as colunas
de logL e de entropia somam 1. Como metade dos pacotes são ACKs TCP (64 zeros) e 485 mil
payloads SOME/IP são todos zero, o byte 0x00 domina quase todas as posições: na prática, o
modelo mede quantos bytes diferentes de zero o pacote tem, ponderados pela raridade.

**Hamming (cols. 6, 10, 11).** `popcount(int(a) XOR int(b))`, com os payloads lidos como
inteiros big-endian: conta **bits** e alinha os payloads **pelo fim** (zeros à esquerda), sem
truncar.

**Normalização.** Min-max sobre o conjunto inteiro (treino e teste, todos os arquivos).

## Montagem do dataset e divisão

Os arrays são `[benigno | ataques | normais dos PCAPs de ataque]`. Os arquivos aparecem nos
ataques na ordem DoS, MITM single, MITM multi, Fuzzy(2), Fuzzy(3), Fuzzy(1), e nos normais na
ordem Fuzzy(2), Fuzzy(3), Fuzzy(1), DoS, MITM single, MITM multi.

**A divisão "estratificada 50/50" é pacote sim, pacote não sobre o array global**: índices
pares no treino, ímpares no teste. Todo pacote de teste tem o vizinho imediato no treino, e o
modelo de bytes foi ajustado com o arquivo benigno inteiro, inclusive a metade de teste.

## Rótulo

O rótulo não é "IP de origem do atacante" nem "MAC de origem do atacante". O conjunto exato
está em `kim_attack_idx.npy` (gerado por `scripts/kim_label_rule.py`). Em relação ao rótulo
pelo MAC de origem:

| arquivo | o Kim marca também como ataque | o Kim marca como normal, embora venha do atacante |
|---|---|---|
| DoS | 41.310 SD unicast das vítimas para o atacante (.2/.3/.7/.9 → .11) e algumas trocas SD com a VDE | 202 segmentos TCP do atacante |
| MITM single | 47.078, o mesmo padrão (→ .13) | 12 |
| MITM multi | 2.851 SD das vítimas para a VDE | **255.035: todo o TCP interno do relay** (.15 → .14 porta 30601; .14 → .10 porta 30501) |
| Fuzzy(2) | 8.370 SD entre vítimas e .12 ou .10 | 228 |
| Fuzzy(1), Fuzzy(3) | — | — (idêntico ao rótulo por IP) |

## Reprodução com o extrator fiel

Rótulo do Kim, XGBoost com os hiperparâmetros da Tabela 2. Os JSON saem em `--out`
(`kim_experiments.json`, `kim_multiclass.json`).

**Binário** (`scripts/kim_experiments.py`, limiar 0,36):

| divisão | ROC-AUC | PR-AUC | F1 ataque | recall | FP |
|---|---|---|---|---|---|
| do Kim (par/ímpar), vetores reconstruídos | 0,987 | 0,932 | 0,845 | 0,74 | 0,18% |
| temporal 70/30 por arquivo | 0,985 | 0,922 | 0,820 | 0,76 | 1,20% |
| temporal, modelo de bytes ajustado só no treino | 0,984 | 0,919 | | | 1,35% |

**Multiclasse, 5 classes** (`scripts/kim_multiclass.py`, família pelo arquivo):

| divisão | macro-F1 | FP | F1 DoS | F1 Fuzzy | F1 MITM single | F1 MITM multi |
|---|---|---|---|---|---|---|
| do Kim (par/ímpar) | 0,816 | 0,07% | 0,750 | 0,515 | 0,844 | 0,987 |
| temporal 70/30 | 0,783 | 0,31% | 0,622 | 0,551 | 0,778 | 0,984 |

Com as 12 features, 64% do Fuzzy é classificado como normal, e DoS e MITM single se confundem
entre si (na divisão temporal, 35% do DoS vira MITM single).

**12 × 16 features** (`scripts/kim_c1_multiclass.py`; as 4 da C1 calculadas sobre as mesmas linhas),
divisão temporal 70/30, F1:

| | rótulo do Kim, 12 | rótulo do Kim, 16 | rótulo por MAC, 12 | rótulo por MAC, 16 |
|---|---|---|---|---|
| macro-F1 | 0,783 | 0,921 | 0,728 | 0,906 |
| FP | 0,31% | 0,23% | 0,36% | 1,08% |
| normal | 0,982 | 0,999 | 0,973 | 0,994 |
| DoS | 0,622 | 0,797 | 0,612 | 0,812 |
| Fuzzy | 0,551 | 0,992 | 0,547 | 0,996 |
| MITM single | 0,778 | 0,834 | 0,779 | 0,832 |
| MITM multi | 0,984 | 0,981 | 0,731 | 0,897 |

Na divisão do Kim, com o rótulo do Kim: 0,816 com 12 e 0,972 com 16. As 4 features da C1 resolvem o
Fuzzy em todos os cenários. A confusão DoS ↔ MITM single persiste com as 12 colunas fiéis (cerca de 30%
do DoS vira MITM single), o que não ocorria com o extrator anterior da C1, que usava o pacote anterior
do mesmo fluxo.

## Pacote anterior por fluxo e mutação de sinais

**Por fluxo** (`scripts/kim_fluxo.py`, `por_fluxo=True` em `src/kim_faithful.py`): as colunas 6 a 11
usam o pacote anterior do mesmo fluxo, como o texto do artigo descreve. Temporal 70/30, rótulo por MAC:

| | anterior global | anterior por fluxo |
|---|---|---|
| 12 features, macro-F1 | 0,728 | 0,762 |
| 16 features, macro-F1 | 0,906 | **0,972** (DoS 0,998; MITM single 0,994; MITM multi 0,878; FP 1,27%) |

A confusão DoS ↔ MITM single vinha dos pacotes de SD que os dois injetores compartilham (Offer de
0x1001 e SubscribeAck); o tempo e as variações dentro do fluxo os separam.

**Mutação** (`scripts/kim_mutacao.py`): o benigno do Kim com um único campo alterado (tamanhos e tempos
idênticos), modelos de bytes do benigno original, últimos 30%, FP (pacotes normais classificados
como ataque):

| perfil | pacotes alterados | 16 por fluxo | 12 por fluxo |
|---|---|---|---|
| original | 0 | 0,038% | 0,264% |
| velocidade do GPS × 1,1 | 177.918 | 0,042% | 0,663% |
| velocidade do GPS + 2 m/s | 177.918 | 0,037% | 0,290% |
| campo A do VDE (quase sempre 0) fixo em 16 | 491.064 | 0,913% | 3,38% |
| campo A do VDE variando (condução) | 491.064 | **10,6%** (quase tudo como MITM single) | 2,29% |

O modelo tolera mudanças em sinais que já variavam no treino (a velocidade do GPS tem ~2 mil valores
distintos) e dispara quando um sinal quase constante no treino passa a variar. Como o MITM single
injeta notificações forjadas do mesmo serviço 0x1001, "conteúdo incomum do VDE" virou, para o modelo,
o próprio sinal do ataque.

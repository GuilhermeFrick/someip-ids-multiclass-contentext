# Resultados publicados

`results/` está no `.gitignore`, porque é saída de execução: se apagar, roda de
novo. Esta pasta é a exceção. São os dez JSON cujos números **aparecem no artigo**,
e três deles medem tempo numa máquina específica que não existe mais.

| arquivo | gerado por | o que sustenta |
|---|---|---|
| `selecao_hiperparametros.json` | `select_hyperparams.py` | escolha de 25 estimadores / profundidade 8, em validação |
| `ablacao_features.json` | `ablate_features.py` | ablação por subconjunto, F1 por classe |
| `leave_one_out.json` | `loo.py` | contribuição individual das quatro features propostas |
| `cost_by_category.json` | `cost_profile.py` | **decomposição do custo de extração por categoria** |
| `latency_sample.json` | `latency_run.py` | **latência por estágio, fim a fim** |
| `latency_quota.json` | `latency_run.py` | **cota de latência por taxa de pacotes** |
| `metrics_temporal.json` | `run_experiment.py` | métricas no split temporal |
| `perclass.json` | `run_experiment.py` | F1 por classe, 12 contra 16 features |
| `macro_auc.json` | `run_experiment.py` | AUC macro, 12 contra 16 features |
| `content_idx.json` | `run_experiment.py` | índices das 16 features |

## A máquina das medições de tempo

Os três arquivos em negrito foram medidos numa instância EC2 efêmera. Só
`metrics_temporal.json` guarda o registro da máquina:

```
platform      Linux-6.17.0-1017-aws-x86_64-with-glibc2.39
processor     x86_64
cpu_logical   8
cpu_physical  8
ram_gb        16.4
```

Os JSON de custo e de latência **não registram a máquina**. Quem for citar esses
microssegundos tem que vir buscar o registro aqui. Vale corrigir nos scripts:
`pipeline.machine_info()` já existe e é o que `run_experiment.py` usa.

## Desvio por categoria, em `cost_by_category.json`

A decomposição foi medida com `n_packets = 200000` e `reps = 7`, e cada categoria
traz seu próprio desvio padrão:

| categoria | média (µs/pacote) | desvio |
|---|---:|---:|
| Source diversity | 9,132 | 0,208 |
| Payload likelihood | 3,553 | 0,010 |
| Payload entropy | 3,320 | 0,011 |
| Payload changes | 2,290 | 0,020 |
| Payload repetition | 0,550 | 0,053 |
| Time interval | 0,511 | 0,005 |
| Absolute size | 0,114 | 0,037 |
| Length changes | 0,085 | 0,017 |

Mais `parse = 2,350` e `total = 21,905`.

Os desvios diferem por duas ordens de grandeza entre categorias, então **não existe
uma incerteza global de ±0,2 µs**: esse é o desvio da categoria mais cara. As duas
categorias mais baratas estão bem resolvidas em relação ao próprio desvio: *Length
changes* a 5σ de zero e *Absolute size* a 3σ. Quem citar essa tabela deve usar o
desvio da linha, não um valor único para todas.

## Cuidado com `metrics_temporal.json`

Ele foi gerado **antes** da seleção de hiperparâmetros: registra
`n_estimators = 300, max_depth = 8`, a configuração antiga. O modelo final tem 25
estimadores. As métricas de detecção ali não são as do modelo final, e sim as do
baseline que `select_hyperparams.py` substituiu (0,9640 contra 0,9689 de macro-F1).

✅ **Confirmado em 01/11/2026, com a VM de treino religada:** o `metrics_temporal.json` que estava
lá é **byte a byte igual** a este. Não existe uma versão mais recente dele em lugar nenhum — o
`run_experiment.py` nunca foi rodado de novo depois da seleção. Quem precisar das métricas do
modelo adotado tem de rodar o experimento outra vez, e os artefatos para isso estão em
[`artefatos-treino/`](../artefatos-treino/).

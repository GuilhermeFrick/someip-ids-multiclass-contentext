**Tabela XIII (FP em janela benigna, % dos quadros rotulados normais na janela de teste de cada captura)**

| captura | β→β | β→γ | γ→γ | γ→β |
|---|---:|---:|---:|---:|
| benign | 0.033% | 17.895% | 0.273% | 1.692% |
| dos | 0.007% | 1.848% | 0.015% | 0.989% |
| fuzzy1 | 0.024% | 20.546% | 0.640% | 1.738% |
| fuzzy2 | 0.028% | 3.203% | 0.061% | 1.568% |
| fuzzy3 | 0.013% | 1.809% | 0.031% | 1.438% |
| mitm_multi | 6.635% | 25.176% | 4.996% | 10.795% |
| mitm_single | 0.014% | 1.922% | 0.063% | 5.464% |
| **todas** | 1.068% | 11.744% | 0.927% | 3.525% |

**Tabela XIV (F1 por classe e macro-F1)**

| classe | β→β | β→γ | γ→γ | γ→β |
|---|---:|---:|---:|---:|
| normal | 0.9945 | 0.9220 | 0.9906 | 0.9600 |
| dos | 0.9981 | 0.8337 | 0.9862 | 0.8955 |
| fuzzy | 0.9991 | 0.4328 | 0.9643 | 0.7196 |
| mitm_single | 0.9947 | 0.4074 | 0.9812 | 0.4137 |
| mitm_multi | 0.8580 | 0.3584 | 0.8332 | 0.5216 |
| **macro-F1** | 0.9689 | 0.5909 | 0.9511 | 0.7021 |

**Recall por classe de ataque**

| classe | β→β | β→γ | γ→γ | γ→β |
|---|---:|---:|---:|---:|
| dos | 0.9994 | 0.7798 | 0.9948 | 0.9509 |
| fuzzy | 0.9991 | 0.5620 | 0.9547 | 0.5677 |
| mitm_single | 0.9999 | 0.8814 | 0.9827 | 0.4627 |
| mitm_multi | 0.9880 | 0.2759 | 0.8343 | 0.5218 |

**Variante: β rotulado por MAC (mesmos modelos)**

| | β→β (MAC) | γ→β (MAC) |
|---|---:|---:|
| FP benign | 0.033% | 1.692% |
| FP dos | 0.007% | 0.989% |
| FP fuzzy1 | 0.024% | 1.738% |
| FP fuzzy2 | 0.028% | 1.568% |
| FP fuzzy3 | 0.013% | 1.438% |
| FP mitm_multi | 7.223% | 2.888% |
| FP mitm_single | 0.014% | 5.464% |
| F1 normal | 0.9879 | 0.9662 |
| F1 dos | 0.9981 | 0.8955 |
| F1 fuzzy | 0.9991 | 0.7196 |
| F1 mitm_single | 0.9947 | 0.4137 |
| F1 mitm_multi | 0.7335 | 0.4364 |
| macro-F1 | 0.9427 | 0.6863 |
| recall dos | 0.9994 | 0.9509 |
| recall fuzzy | 0.9991 | 0.5677 |
| recall mitm_single | 0.9999 | 0.4627 |
| recall mitm_multi | 0.7104 | 0.3751 |

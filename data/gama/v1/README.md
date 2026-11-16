# Dataset γ: tráfego SOME/IP gerado pela bancada com o CARLA

> **Neste repositório** os arquivos grandes estão comprimidos e no Git LFS (`scn.pcap.gz`,
> `scn.labels.gz`, `viagem.csv.gz`). Para usar: `git lfs pull && bash data/gama/prepara.sh`, que
> descomprime e confere o SHA-256 (`data/gama/SHA256SUMS`). Os logs da geração (`log-*.txt`) não
> foram versionados. A avaliação entre domínios está em `experiments/cross-domain/`.


Captura de tráfego SOME/IP **real** (pilha vSomeIP 3.5.6, nós C++ em containers, quadros Ethernet
capturados no barramento) de um barramento com **a mesma matriz de comunicação do dataset do Kim**
(β), em que o conteúdo das mensagens vem de um veículo conduzido no **CARLA 0.9.15**. São as mesmas
**sete capturas** de β, uma sem ataque e seis com um ataque cada, com os mesmos atacantes.

Serve para medir se um detector treinado em β generaliza para tráfego de outra origem (β → γ) e,
como controle, se γ é aprendível por si (γ → γ).

> Números de volume e duração: seção [Composição](#composição), preenchida a partir de `RESUMO.txt`.

## Onde está e o que tem

Gerado por `platform/carla-live/gera_gama.sh` (commit de origem em `PROCEDENCIA.txt`). Na máquina do
CARLA, em `~/gama/v1/`:

```
v1/
├── PROCEDENCIA.txt        data, máquina, GPU, commit, parâmetros e md5 da matriz e das fontes
├── RESUMO.txt             uma linha por captura: quadros, quadros de ataque, fator de tempo real
├── benign/  dos/  fuzzy1/  fuzzy2/  fuzzy3/  mitm_single/  mitm_multi/
│   ├── scn.pcap           a captura do barramento (pcap clássico, Ethernet)
│   ├── scn.labels         o rótulo de cada quadro: "<índice> <classe>"
│   ├── injector.mac       MAC e papel de cada atacante (fonte do rótulo)
│   ├── linha-do-tempo.txt quando cada nó e cada atacante subiu (T0_EPOCH + segundos)
│   ├── viagem.csv         a viagem do CARLA que alimentou a captura (100 Hz)
│   └── log-*.txt          logs dos nós, da ponte e dos atacantes
└── <captura>.log          log da rodada
```

Classes do `scn.labels`: **0** normal, **1** DoS, **2** Fuzzy, **3** MITM single, **4** MITM multi.
O índice é a posição do quadro no `scn.pcap`, a partir de 0.

## O barramento

A matriz é a recuperada do PCAP benigno do Kim (`platform/comm_matrix_kim.yaml`), na sub-rede
`172.28.0.0/24` em vez de `172.18.0.0/24`.

| Serviço | Provedor | Eventos (ciclo, payload) | Método |
|---|---|---|---|
| 0x1001 (VDE) | .10 | 0x0001 10,1 ms 24 B · 0x0002 5,1 ms 24 B · 0x0003 15,1 ms 16 B · 0x0004 25,1 ms 24 B | 0x0001, máscara de 18 sinais |
| 0x1002 (IMU) | .5 | 0x0001 10,1 ms 16 B · 0x0002 15,1 ms 32 B · 0x0003 10,1 ms 16 B · 0x0004 25,1 ms 16 B | 0x0001, máscara de 7 sinais |
| 0x1003 (GPS) | .4 | 0x0001 25,1 ms 40 B · 0x0002 25,0 ms 40 B · 0x0003 25,1 ms 24 B | 0x0001, máscara de 6 sinais |

- **Assinantes:** ADAS .2 (evento 1 dos três serviços), CLU .3, NAV .6, PT .7, STE .8, TEL .9.
- **Service Discovery:** multicast 224.244.224.245:30490, oferta cíclica a cada 2 s.
- **Transporte:** notificações por TCP; o resultado é ~98% de TCP nos quadros, contra 99,1% em β.
- **Request/response:** a ADAS (client id 0x1012) chama o método 0x0001 dos três serviços por UDP,
  num tique de 500 ms, com probabilidade de ~0,18 a 0,19 por tique. O pedido é uma máscara `uint32`
  little-endian; a resposta traz um double por bit ligado. Formato e ritmo medidos em β.

## O conteúdo: de onde vêm os valores

A ponte (`carla/cliente/carla_trip.py`, tradução em `carla/cliente/sinais_someip.py`) roda o CARLA
em modo síncrono com passo de 10 ms, preso ao relógio (1,0× do tempo real, sem renderizar), com o
veículo e 40 outros no Traffic Manager. A cada passo ela manda às três ECUs provedoras os campos
abaixo, como doubles little-endian; cada ECU publica o último valor na cadência da matriz.

| Evento | Campos |
|---|---|
| VDE 0x0001 | v, freio, aceleração lateral |
| VDE 0x0002 | freio, v, aceleração lateral |
| VDE 0x0003 | v, freio |
| VDE 0x0004 | v, freio, volante |
| IMU 0x0001 | rumo, 1 |
| IMU 0x0002 | 0, 1, 0, rumo |
| IMU 0x0003 | rumo, 1 |
| IMU 0x0004 | rumo atrasado 0,5 s, 1 |
| GPS 0x0001 | x, y, 0, v, v·T |
| GPS 0x0002 | x, y, 0, v, 0 |
| GPS 0x0003 | x, y, v |

A resposta de um método traz os doubles que o provedor publicou por último, evento após evento,
com zero nos bits além deles. `viagem.csv` guarda a viagem a 100 Hz
(`t, v, a_long, a_lat, rumo, guinada, volante, x, y`).

## Os ataques

Os mesmos de β, todos pelo Service Discovery, com o mesmo IP e a mesma ordem de entrada:

| Captura | Atacante | O que faz |
|---|---|---|
| `dos` | .11 | Sobe antes da VDE e oferece 0x1001 a cada 20 ms; as vítimas ficam com ele |
| `fuzzy1` | .17 | Oferece ~200 serviços inexistentes (0x2001–0x20C8) pelo SD; só SD |
| `fuzzy2` | .12 | Oferece 0x1001 com a VDE no ar, ~0,45 s antes dela; só o evento 0x0001, aleatório, a cada 10 ms. A ADAS recebe Ack; CLU, PT e TEL recebem Nack e reconectam. Responde aos métodos da ADAS |
| `fuzzy3` | .12 | A VDE não sobe; o .12 é o programa da VDE, com o evento 0x0001 aleatório (cada valor em duas publicações). Responde aos métodos |
| `mitm_single` | .13 | Entra ~3 s depois da VDE, oferece 0x1001 a cada 10 ms e manda StopOffer à ADAS do próprio IP a cada 2,5 s |
| `mitm_multi` | .14 + .15 | O .14 assina a VDE e republica em 0x100B; o .15 oferece 0x1001 e manda à ADAS um StopOffer com **o IP da VDE forjado** a cada valor repassado |

Os atacantes que se passam pela VDE no DoS e no MITM single **não** respondem aos métodos, como em
β (0 de 528 e 0 de 447 pedidos). Comparação com β, número a número, em
`platform/scenario-live/README.md` e `docs/ataques-kim.md`.

## O rótulo

Por **MAC de origem**: cada atacante tem um MAC fixo (`injector.mac`), e todo quadro que ele põe no
fio é da classe do ataque; o resto é normal. β rotula por IP de origem, e essa regra marca como
normais os StopOffer forjados do MITM multi (eles saem com o IP da VDE). Por isso a classe 4 de γ
inclui esses quadros, e a de β não.

## O que é diferente de β

| Diferença | Por quê |
|---|---|
| O conteúdo dos payloads | É o objetivo: em β os sinais são quase constantes (VDE com payload zero em 98–99% das notificações, velocidade em patamares); em γ vêm de um veículo andando |
| Sub-rede 172.28.0.x | Rede Docker da bancada; nenhuma feature usa o endereço |
| Rótulo por MAC | Ver acima |
| Ordem de subida dos consumidores | Em β a ADAS sobe aos ~9,6 s; em γ, primeiro |
| A taxa da VDE é constante | Em β ela cai ao longo do arquivo (de ~24 mil para ~15 mil notificações por minuto), artefato do gerador de β |
| Os métodos respondem o arquivo todo | Em β a VDE e a IMU param de responder aos ~1.131 s |
| Fuzzy 2: fase da oferta calibrada por máquina | `FUZZ2_LAG` (0,12 s na máquina do CARLA) |

## Composição

Gerado em 15/11/2026 (commit de origem `c8de8f7`), na máquina do CARLA (Tesla T4, 8 vCPU). Cada
captura dura 1.500 s e rodou a 1,0× do tempo real (1.500 a 1.521 s de relógio). Na coluna de β,
os números são os de quadros de ataque do dataset do Kim, para comparação.

| Captura | Quadros | Benignos | Ataque | % ataque | Ataque em β | % em β |
|---|---|---|---|---|---|---|
| benign | 2.499.419 | 2.499.419 | 0 | 0,0% | 0 | 0,0% |
| dos | 2.025.455 | 1.643.926 | 381.529 | 18,8% | 306.944 | 16,5% |
| fuzzy1 | 2.522.374 | 2.517.104 | 5.270 | 0,2% | 5.243 | 0,2% |
| fuzzy2 | 1.404.666 | 1.357.005 | 47.661 | 3,4% | 43.213 | 3,3% |
| fuzzy3 | 2.498.716 | 1.892.397 | 606.319 | 24,3% | 511.596 | 23,0% |
| mitm_single | 2.488.930 | 1.876.712 | 612.218 | 24,6% | 360.510 | 17,7% |
| mitm_multi | 2.666.765 | 2.051.220 | 615.545 | 23,1% | 427.493 | 17,7% |
| **Total** | **16.106.325** | **13.837.783** | **2.268.542** | **14,1%** | **1.654.999** | **11,6%** |

Leitura da comparação:

- **Fuzzy 1 e Fuzzy 2** batem com β quase quadro a quadro (5.270 contra 5.243; 47.661 contra 43.213).
- **DoS e Fuzzy 3** ficam um pouco acima. Em β a taxa da VDE, que o atacante do Fuzzy 3 imita, cai
  ao longo do arquivo; na bancada ela é constante.
- **MITM multi** fica acima em parte por causa do rótulo: o rótulo por MAC conta como ataque os
  StopOffer forjados com o IP da VDE, que o rótulo por IP de β conta como normais.
- **MITM single** fica 70% acima de β, e a causa **ainda não foi investigada**. Antes de usar a
  classe em conclusões, é preciso comparar a taxa de cada tipo de mensagem do atacante com a de β.

Verificações feitas sobre a geração:

- **Segmentação TCP:** nas 7 capturas, todo segmento TCP com *payload* carrega exatamente uma
  mensagem SOME/IP completa (no máximo 56 bytes com o cabeçalho), como em β. O extrator, que lê
  segmento a segmento, se aplica sem remontagem.
- **Condução:** o veículo anda durante toda a captura. A velocidade média é de ~4,5 m/s e o carro
  fica parado ~1/3 do tempo (semáforos e tráfego do Town10HD com 40 veículos): condução urbana e
  lenta, mas com sinais que variam continuamente, ao contrário dos patamares de β.

## Como gerar de novo

Na máquina do CARLA (GPU NVIDIA), com o servidor no ar (`bash carla/infra/subir.sh`):

```bash
GIT_REV=$(git rev-parse --short HEAD) nohup bash platform/carla-live/gera_gama.sh > ~/gama.out 2>&1 &
```

Cada captura tem a sua semente de viagem (101 a 107, na ordem da tabela acima). `CAPTURAS="..."`
gera só algumas; `DUR`, `RENDER`, `FUZZ2_LAG` e `GAMA` mudam duração, renderização, fase do Fuzzy 2
e diretório de saída.

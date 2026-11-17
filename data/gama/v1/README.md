# Tráfego SOME/IP gerado com o simulador CARLA (amostras benignas e de ataque)

Capturas de pacotes de uma rede SOME/IP com nove ECUs, em que os sinais transportados vêm de um
veículo conduzido no simulador de direção CARLA. Há uma captura de tráfego normal e seis capturas
com ataque, cada uma com 1.500 s (25 min), em PCAP, com o rótulo de cada quadro em um arquivo à
parte.

O dataset foi construído para avaliar se um detector de intrusão treinado em um dataset público de
SOME/IP continua funcionando quando o tráfego vem de outra origem. Por isso ele reproduz a rede, as
cadências e os ataques do dataset de referência de Kim (*SOME/IP traffic (Benign and Attack
samples)*, figshare, DOI [10.6084/m9.figshare.30970450](https://doi.org/10.6084/m9.figshare.30970450),
CC BY 4.0) e muda só a origem dos dados: no dataset de referência os sinais ficam quase constantes;
aqui eles vêm de um carro andando pela cidade.

| | |
|---|---|
| Pasta neste repositório | `data/gama/v1/` |
| Capturas | 7 (1 normal, 6 com ataque), 1.500 s cada |
| Quadros | 16.106.325 no total |
| Formato | PCAP clássico (Ethernet), rótulo por quadro em texto |
| Gerado em | 15/11/2026 |
| Licença | a definir |

## Como baixar

Os arquivos grandes estão comprimidos no Git LFS. A partir da raiz do repositório:

```bash
git lfs pull
bash data/gama/prepara.sh
```

O `prepara.sh` descomprime cada `.gz` ao lado do original e confere o SHA-256 de todos os arquivos
contra `data/gama/SHA256SUMS`.

## Visão geral

- **Rede:** nove ECUs SOME/IP numa mesma sub-rede Ethernet (`172.28.0.0/24`), cada uma em um
  container próprio com IP e MAC fixos.
- **Pilha:** vSomeIP 3.5.6 (implementação de referência do SOME/IP), com nós escritos em C++.
- **Comunicação:**
  - *publish/subscribe*: três ECUs provedoras publicam eventos periódicos, e seis ECUs assinantes
    os recebem por TCP;
  - *request/response*: a ECU de ADAS chama um método de cada provedor, por UDP;
  - *Service Discovery* (SOME/IP-SD): ofertas e assinaturas em multicast UDP.
- **Origem dos dados:** o CARLA 0.9.15 conduz o veículo, e o estado dele (velocidade, aceleração,
  rumo, posição) vira o conteúdo das mensagens.
- **Captura:** um monitor passivo grava todo o tráfego da rede, inclusive o unicast entre quaisquer
  dois nós.
- **Ataques:** um ou dois nós atacantes, com IP e MAC próprios, entram na rede durante a captura.
  Os quatro tipos de ataque (DoS, *Fuzzy* e dois *man-in-the-middle*) exploram o mesmo ponto: o
  SOME/IP-SD não autentica quem anuncia nem quem retira um serviço.

## Como o tráfego é produzido

Nenhuma captura é reproduzida (*replay*): cada uma é gerada do zero, com o tráfego produzido pelas
ECUs em tempo de execução. Do dataset de referência vêm só a configuração da rede e os *payloads*
publicados pelos atacantes.

```
 CARLA 0.9.15                   ponte                       9 ECUs (vSomeIP)            monitor
 ┌──────────────┐  estado do    ┌───────────────┐ payloads  ┌──────────────────┐ tráfego ┌──────────┐
 │ veículo + 40 │──── carro ───▶│ estado →      │──────────▶│ 3 provedoras     │────────▶│ scn.pcap │
 │ outros, a    │  a cada 10 ms │ payload de    │  (rede de │ 6 assinantes     │  rede   └────┬─────┘
 │ 100 Hz       │               │ cada evento   │  controle,│ + atacante(s)    │  SOME/IP     │ MAC de
 └──────────────┘               └───────────────┘  fora da  └──────────────────┘              ▼ origem
                                                    captura)                             scn.labels
```

1. **Condução.** O CARLA roda em modo síncrono, com passo fixo de 10 ms, no mapa Town10HD. O
   veículo e outros 40 são conduzidos pelo *Traffic Manager* (o piloto automático do CARLA), com
   semáforos e trânsito. A simulação é segurada ao relógio (1,0× do tempo real) e roda sem
   renderizar. Cada captura tem uma viagem própria (sementes 101 a 107).
2. **Tradução.** A cada passo, uma ponte converte o estado do veículo no *payload* de cada evento
   (seção [Conteúdo das mensagens](#conteúdo-das-mensagens)) e o envia às três ECUs provedoras por
   uma rede de controle separada, que não é capturada.
3. **Publicação.** Cada ECU provedora publica o último valor recebido na cadência que a matriz de
   comunicação define para aquele evento (de 5 a 25 ms).
4. **Consumo.** As ECUs assinantes descobrem os serviços pelo SOME/IP-SD, assinam os grupos de
   eventos que consomem e recebem as notificações. A ECU de ADAS também faz chamadas de método.
5. **Ataque.** Nas capturas com ataque, o(s) nó(s) atacante(s) sobe(m) no momento indicado em
   `linha-do-tempo.txt` e fica(m) ativo(s) até o fim.
6. **Captura e rótulo.** O monitor grava a interface da rede durante 1.500 s. No fim, cada quadro
   recebe o rótulo pelo MAC de origem (seção [Rótulos](#rótulos)).

A configuração da rede (serviços, eventos, cadências, tamanhos, endereços e métodos) foi extraída
uma única vez da captura normal do dataset de referência e está versionada como uma matriz de
comunicação. Os ataques foram reconstruídos a partir das capturas de ataque do mesmo dataset e
conferidos contra elas (seção [Relação com o dataset de referência](#relação-com-o-dataset-de-referência)).

## ECUs e serviços

Os nomes das ECUs seguem os do artigo de Kim. O MAC de cada nó segue o padrão do Docker,
`02:42:ac:1c:00:XX`, em que `XX` é o último byte do IP em hexadecimal (por exemplo, `.10` →
`02:42:ac:1c:00:0a`).

| IP | ECU | Papel | Oferece | Assina (serviço: grupo de eventos) |
|---|---|---|---|---|
| 172.28.0.2 | ADAS | assinante; chama métodos | | 0x1001: 1 · 0x1002: 1 · 0x1003: 1 |
| 172.28.0.3 | CLU | assinante | | 0x1001: 3 |
| 172.28.0.4 | GPS | provedora | 0x1003 | |
| 172.28.0.5 | IMU | provedora | 0x1002 | |
| 172.28.0.6 | NAV | assinante | | 0x1002: 2 · 0x1003: 2 |
| 172.28.0.7 | PT | assinante | | 0x1001: 2 |
| 172.28.0.8 | STE | assinante | | 0x1002: 3 |
| 172.28.0.9 | TEL | assinante | | 0x1001: 4 · 0x1002: 4 · 0x1003: 3 |
| 172.28.0.10 | VDE (dinâmica do veículo) | provedora | 0x1001 | |

Cada grupo de eventos contém um único evento, com o mesmo número (o grupo 1 contém o evento
0x0001, e assim por diante).

| Serviço (instância) | Provedora | Portas anunciadas | Eventos: ciclo, tamanho do *payload* | Método |
|---|---|---|---|---|
| 0x1001 (0x0001) | VDE .10 | TCP 30501, UDP 31097 | 0x0001: 10,1 ms, 24 B · 0x0002: 5,1 ms, 24 B · 0x0003: 15,1 ms, 16 B · 0x0004: 25,1 ms, 24 B | 0x0001, 18 sinais |
| 0x1002 (0x0002) | IMU .5 | TCP 30502, UDP 31098 | 0x0001: 10,1 ms, 16 B · 0x0002: 15,1 ms, 32 B · 0x0003: 10,1 ms, 16 B · 0x0004: 25,1 ms, 16 B | 0x0001, 7 sinais |
| 0x1003 (0x0003) | GPS .4 | TCP 30503, UDP 31099 | 0x0001: 25,1 ms, 40 B · 0x0002: 25,0 ms, 40 B · 0x0003: 25,1 ms, 24 B | 0x0001, 6 sinais |

- **Notificações de evento:** por TCP. Cada segmento TCP carrega exatamente uma mensagem SOME/IP
  completa (no máximo 56 bytes com o cabeçalho), então a captura pode ser lida segmento a segmento,
  sem remontar o fluxo TCP.
- **Service Discovery:** multicast `224.244.224.245`, porta UDP 30490, com oferta cíclica a cada 2 s.
- **Métodos:** a ADAS (*client ID* 0x1012) chama o método 0x0001 dos três serviços por UDP. A cada
  500 ms ela sorteia, para cada serviço, se faz a chamada (probabilidade de 0,18 a 0,19). O pedido
  é uma máscara `uint32` *little-endian* que escolhe os sinais; a resposta traz um `double` por bit
  ligado.

## Conteúdo das mensagens

Todos os campos são `double` *little-endian* (8 bytes cada), na ordem abaixo.

| Serviço | Evento | Campos |
|---|---|---|
| 0x1001 VDE | 0x0001 | v, freio, lat |
| | 0x0002 | freio, v, lat |
| | 0x0003 | v, freio |
| | 0x0004 | v, freio, volante |
| 0x1002 IMU | 0x0001 | rumo, 1 |
| | 0x0002 | 0, 1, 0, rumo |
| | 0x0003 | rumo, 1 |
| | 0x0004 | rumo de 0,5 s atrás, 1 |
| 0x1003 GPS | 0x0001 | x, y, 0, v, v × período do evento |
| | 0x0002 | x, y, 0, v, 0 |
| | 0x0003 | x, y, v |

- `v`: velocidade (m/s);
- `freio`: desaceleração longitudinal (m/s², zero ou negativa);
- `lat`: aceleração lateral, v × taxa de guinada (m/s²);
- `volante`: ângulo de esterçamento estimado pela guinada (rad, de 0 a 0,6);
- `rumo`: direção do veículo (rad, acumulada, sem dar a volta em 2π);
- `x`, `y`: posição no mapa (m).

A posição e a ordem dos campos são as mesmas do dataset de referência, recuperadas dos seus
*payloads*. A resposta de um método traz os valores que a provedora publicou por último, na ordem
dos eventos, com zero nos bits além deles.

Nas viagens, o veículo anda durante toda a captura, a ~4,5 m/s em média, e fica parado cerca de
um terço do tempo, em semáforos e no trânsito. É uma condução urbana e lenta, mas com sinais que
variam continuamente. A viagem de cada captura está em `viagem.csv` (100 Hz), com as colunas `t`
(s), `v` (m/s), `a_long` (m/s²), `a_lat` (m/s²), `rumo` (rad), `guinada` (rad/s), `volante` (-1 a
1) e `x`, `y` (m).

## Cenário normal (`benign/`)

As nove ECUs sobem nos primeiros 4 s (provedoras primeiro) e trocam tráfego normalmente durante os
1.500 s, sem nenhum atacante.

## Cenários de ataque

Em todos os cenários, o atacante é um nó adicional na mesma rede, com IP e MAC próprios. Os IPs,
a ordem de entrada e o comportamento reproduzem o atacante correspondente do dataset de referência.
Os *payloads* que os atacantes publicam também vêm de lá (constantes, aleatórios ou o sinal falso
do próprio atacante de referência); só o tráfego legítimo carrega os dados do CARLA.

Os instantes são em segundos desde o início da captura, tirados de `linha-do-tempo.txt`.

### DoS por sequestro do serviço 0x1001 (`dos/`)

O atacante sobe antes da VDE e passa a oferecer o serviço dela. As ECUs que procuram 0x1001
encontram primeiro o atacante e ficam com ele; quando a VDE legítima aparece, as assinaturas nela
são recusadas, e CLU, PT e TEL ficam sem os dados da VDE, reconectando continuamente.

- Atacante: 172.28.0.11, MAC `02:42:ac:1c:00:0b`, sobe aos 0,3 s; a VDE sobe aos 9,4 s.
- **Como identificar o tráfego de ataque:**
  - (A) ofertas falsas no SOME/IP-SD: UDP para a porta 30490, `service_id` 0xFFFF, `method_id`
    0x8100, entrada *OfferService* de 0x1001 (instância 0x0001) com o endpoint do atacante, a cada
    ~20 ms;
  - (B) notificações forjadas à ADAS: `service_id` 0x1001, evento 0x0001, por TCP, ~50 por
    segundo, com *payload* constante;
  - (C) respostas de SD (*SubscribeAck* e *SubscribeNack*) e a sinalização TCP do atacante.

### *Fuzzy* 1: inundação de identificadores no SOME/IP-SD (`fuzzy1/`)

O atacante anuncia no SD cerca de 200 serviços que não existem. Ninguém assina nem conecta neles,
e o resto da rede continua funcionando normalmente.

- Atacante: 172.28.0.17, MAC `02:42:ac:1c:00:11`, sobe aos 14,6 s.
- **Como identificar o tráfego de ataque:** ofertas de SD (UDP 30490, `service_id` 0xFFFF,
  `method_id` 0x8100) com entradas *OfferService* para os serviços 0x2001 a 0x20C8, com instância
  igual ao serviço. Só UDP, só SD.

### *Fuzzy* 2: disputa pela oferta de 0x1001, com notificações aleatórias (`fuzzy2/`)

O atacante oferece o serviço 0x1001 com a VDE no ar, ~0,45 s antes de cada oferta dela, no mesmo
ritmo de 2 s, como na referência (a fase é calibrada por máquina, pelo parâmetro `FUZZ2_LAG`). A pilha das assinantes segue quem anunciou por último: a cada oferta do atacante a
ADAS assina nele e recebe uma rajada de notificações; na oferta seguinte da VDE, a ADAS tenta
voltar e é recusada. CLU, PT e TEL são recusadas pelos dois e reconectam.

- Atacante: 172.28.0.12, MAC `02:42:ac:1c:00:0c`, sobe aos 4,9 s; a VDE sobe aos 5,4 s.
- **Como identificar o tráfego de ataque:**
  - (A) ofertas de 0x1001 no SD (UDP 30490) com o endpoint do atacante;
  - (B) notificações 0x1001, evento 0x0001, à ADAS, a cada 10 ms durante cada rajada, com 24 bytes
    de bits aleatórios (cada valor é publicado duas vezes seguidas);
  - (C) respostas aos pedidos de método da ADAS: o atacante responde no lugar da VDE.

### *Fuzzy* 3: substituição da VDE, com evento 0x0001 aleatório (`fuzzy3/`)

A VDE legítima não sobe. Em seu lugar, o programa da VDE roda no IP do atacante e atende toda a
rede, mas publica o evento 0x0001 com conteúdo aleatório. Os demais eventos (0x0002 a 0x0004)
carregam os dados normais do veículo.

- Atacante: 172.28.0.12, MAC `02:42:ac:1c:00:0c`, sobe aos 5,0 s; não há tráfego de 172.28.0.10.
- **Como identificar o tráfego de ataque:** todo o tráfego de 172.28.0.12: ofertas de 0x1001 no
  SD, as quatro notificações de 0x1001 (o evento 0x0001 com 24 bytes aleatórios, cada valor
  publicado duas vezes) e as respostas aos métodos. Os eventos 0x0002 a 0x0004 são rotulados como
  ataque, embora o conteúdo seja normal, porque vêm do atacante.

### *Man-in-the-middle* com um atacante: *withdraw* e injeção (`mitm_single/`)

O atacante entra depois da VDE, oferece 0x1001 a cada 10 ms e envia periodicamente à ADAS um
*StopOffer* (uma oferta com TTL 0, o *withdraw* do SD) em nome da VDE, a partir do próprio IP. A
ADAS larga a VDE e passa a receber o sinal falso do atacante. CLU, PT e TEL são recusadas pelo
atacante e ficam praticamente sem dados da VDE.

- Atacante: 172.28.0.13, MAC `02:42:ac:1c:00:0d`, sobe aos 7,6 s; a VDE sobe aos 1,0 s.
- **Como identificar o tráfego de ataque:**
  - (A) *withdraw* de SD: UDP de 172.28.0.13 para 172.28.0.2, porta 30490, `service_id` 0xFFFF,
    `method_id` 0x8100, entrada *OfferService* de 0x1001 (instância 0x0001) com TTL 0 e o endpoint
    da VDE (172.28.0.10, TCP 30501, UDP 31097), a cada 2,5 s;
  - (B) ofertas falsas de 0x1001 com o endpoint do atacante, a cada 10 ms;
  - (C) notificações forjadas de 0x1001, evento 0x0001, à ADAS, com o sinal falso do atacante de
    referência (velocidade média de 14,7 m/s).

### *Man-in-the-middle* com dois atacantes: repasse, *withdraw* forjado e impostura (`mitm_multi/`)

Dois nós atuam juntos. O retransmissor assina a VDE como uma ECU comum e republica cada valor
recebido em um serviço próprio. O impostor oferece 0x1001, assina o repasse e, a cada valor
repassado que recebe, manda à ADAS um *StopOffer* com o IP de origem forjado como o da VDE.

- Retransmissor: 172.28.0.14, MAC `02:42:ac:1c:00:0e`, sobe aos 0,3 s, antes da VDE.
- Impostor: 172.28.0.15, MAC `02:42:ac:1c:00:0f`, sobe aos 9,8 s; a VDE sobe aos 6,4 s.
- **Como identificar o tráfego de ataque:**
  - (A) repasse: notificações do serviço 0x100B (instância 0x000B, TCP 30601, UDP 31697), evento
    0x0001, a cada ~9 ms, com cópia do *payload* da VDE;
  - (B) *withdraw* forjado: UDP para 172.28.0.2, porta 30490, *OfferService* de 0x1001 com TTL 0,
    **com IP de origem 172.28.0.10 (o da VDE) e MAC do impostor** (`02:42:ac:1c:00:0f`);
  - (C) impostura: ofertas de 0x1001 com o endpoint do impostor e notificações forjadas de 0x1001
    com *payload* constante.

## Rótulos

`scn.labels` tem uma linha por quadro do `scn.pcap`, no formato `<índice> <classe>`. O índice é a
posição do quadro no PCAP, a partir de 0.

| Classe | Significado |
|---|---|
| 0 | normal |
| 1 | DoS |
| 2 | *Fuzzy* (as três capturas *Fuzzy* usam a mesma classe) |
| 3 | *man-in-the-middle* com um atacante |
| 4 | *man-in-the-middle* com dois atacantes |

**Regra:** todo quadro cujo MAC de origem é o de um atacante (listado em `injector.mac`) recebe a
classe do ataque daquela captura; todos os outros são normais. O rótulo vem do MAC, e não do IP,
porque no *man-in-the-middle* com dois atacantes o impostor forja o IP da VDE: pelo IP, os
166.691 *StopOffers* forjados seriam rotulados como normais. Nas outras seis capturas, o rótulo
pelo MAC e o rótulo pelo IP do atacante coincidem em todos os quadros (conferido em `rotulo.txt`).

## Arquivos

Em cada uma das sete pastas (`benign`, `dos`, `fuzzy1`, `fuzzy2`, `fuzzy3`, `mitm_single`,
`mitm_multi`):

| Arquivo | Conteúdo |
|---|---|
| `scn.pcap.gz` | a captura (PCAP clássico, Ethernet), comprimida |
| `scn.labels.gz` | o rótulo de cada quadro, comprimido |
| `viagem.csv.gz` | a viagem do CARLA que alimentou a captura (100 Hz), comprimida |
| `injector.mac` | MAC e papel de cada atacante (vazio na captura normal) |
| `linha-do-tempo.txt` | o instante em que cada ECU e cada atacante subiu |
| `rotulo.txt` | contagem de quadros por classe e comparação com a regra por IP |

Na raiz de `v1/`: `PROCEDENCIA.txt` (data, máquina, versão do código, parâmetros e md5 da matriz
de comunicação e das fontes) e `RESUMO.txt` (uma linha por captura). Os SHA-256 dos arquivos
descomprimidos estão em `data/gama/SHA256SUMS`.

| Captura | `scn.pcap.gz` | `scn.labels.gz` | `viagem.csv.gz` |
|---|---:|---:|---:|
| benign | 63,1 MB | 5,6 MB | 2,4 MB |
| dos | 46,9 MB | 4,7 MB | 2,4 MB |
| fuzzy1 | 65,8 MB | 5,6 MB | 2,3 MB |
| fuzzy2 | 35,3 MB | 3,2 MB | 2,2 MB |
| fuzzy3 | 65,4 MB | 5,8 MB | 2,5 MB |
| mitm_single | 55,2 MB | 5,9 MB | 2,1 MB |
| mitm_multi | 65,8 MB | 6,2 MB | 2,3 MB |

## Composição

Contagem por quadro, como sai dos arquivos (`rotulo.txt`):

| Captura | Quadros | Normais | Ataque | % ataque |
|---|---:|---:|---:|---:|
| benign | 2.499.419 | 2.499.419 | 0 | 0,0% |
| dos | 2.025.455 | 1.643.926 | 381.529 | 18,8% |
| fuzzy1 | 2.522.374 | 2.517.104 | 5.270 | 0,2% |
| fuzzy2 | 1.404.666 | 1.357.005 | 47.661 | 3,4% |
| fuzzy3 | 2.498.716 | 1.892.397 | 606.319 | 24,3% |
| mitm_single | 2.488.930 | 1.876.712 | 612.218 | 24,6% |
| mitm_multi | 2.666.765 | 2.051.220 | 615.545 | 23,1% |
| **Total** | **16.106.325** | **13.837.783** | **2.268.542** | **14,1%** |

Contagem só dos pacotes IPv4 com TCP ou UDP, que é a usada pelo dataset de referência e pelos
extratores de *features* (ficam de fora, por exemplo, ARP e IGMP):

| Captura | Pacotes | Normais | Ataque | % ataque |
|---|---:|---:|---:|---:|
| benign | 2.498.440 | 2.498.440 | 0 | 0,0% |
| dos | 1.955.856 | 1.642.598 | 313.258 | 16,0% |
| fuzzy1 | 2.521.310 | 2.516.046 | 5.264 | 0,2% |
| fuzzy2 | 1.403.346 | 1.355.695 | 47.651 | 3,4% |
| fuzzy3 | 2.497.677 | 1.891.549 | 606.128 | 24,3% |
| mitm_single | 2.352.507 | 1.875.582 | 476.925 | 20,3% |
| mitm_multi | 2.665.452 | 2.050.273 | 615.179 | 23,1% |
| **Total** | **15.894.588** | **13.830.183** | **2.064.405** | **13,0%** |

## Relação com o dataset de referência

**O que é igual:** a matriz de comunicação (serviços, eventos, cadências, tamanhos, métodos), a
posição dos campos nos *payloads*, os atacantes (IPs, ordem de entrada, mensagens de SD forjadas e
*payloads* publicados) e a duração das capturas. As assinaturas, medidas da mesma forma nos dois
datasets, coincidem:

| Assinatura | Referência | Este dataset |
|---|---:|---:|
| TCP nos pacotes IP da captura normal | 99,0% | 99,1% |
| DoS: ofertas falsas de 0x1001 por segundo | 49,4 | 49,7 |
| *MITM* com um atacante: ofertas de 0x1001 por segundo | 97,5 | 98,7 |
| *MITM* com um atacante: intervalo mediano entre *StopOffers* | 2,50 s | 2,50 s |
| *MITM* com dois atacantes: *StopOffers* com o IP da VDE forjado | 163.188 | 166.691 |
| *MITM* com dois atacantes: quadros do retransmissor / do impostor | 60,5% / 39,5% | 61,4% / 38,6% |

Pacotes de ataque (IPv4 com TCP ou UDP), com o rótulo pelo MAC nos dois datasets:

| Captura | Referência | Este dataset | Diferença |
|---|---:|---:|---:|
| DoS | 306.944 | 313.258 | +2% |
| *Fuzzy* 1 | 5.243 | 5.264 | 0% |
| *Fuzzy* 2 | 43.213 | 47.651 | +10% |
| *Fuzzy* 3 | 511.596 | 606.128 | +18% |
| *MITM* com um atacante | 360.510 | 476.925 | +32% |
| *MITM* com dois atacantes | 590.681 | 615.179 | +4% |

O dataset de referência rotula pelo IP de origem. Por essa regra, a classe do *MITM* com dois
atacantes tem 427.493 pacotes, porque os *StopOffers* com o IP da VDE contam como normais.

**O que é diferente:**

| Diferença | Motivo |
|---|---|
| O conteúdo dos sinais | É o objetivo do dataset. Na referência, a VDE publica *payload* zero em 98 a 99% das notificações e a velocidade fica em patamares; aqui os sinais vêm de um veículo andando |
| Sub-rede 172.28.0.0/24 (na referência, 172.18.0.0/24) | Rede Docker do gerador; o último byte de cada IP é o mesmo |
| A taxa de publicação da VDE é constante | Na referência ela cai ao longo do arquivo (de ~24 mil para ~15 mil notificações por minuto) |
| Os métodos respondem durante toda a captura | Na referência, a VDE e a IMU param de responder aos ~1.131 s |
| Ordem de subida das ECUs assinantes | Na referência, a ADAS sobe aos ~9,6 s; aqui, antes das outras assinantes |

## Pontos em aberto

- ***MITM* com um atacante: 32% mais pacotes de ataque que na referência.** As mensagens de SD
  batem (taxa de ofertas e intervalo entre *StopOffers*), então a diferença está em outro tipo de
  mensagem do atacante. A causa ainda não foi investigada.
- **Volume do tráfego normal:** as capturas têm de 5% a 15% mais pacotes que as da referência,
  inclusive a normal. A origem (confirmações TCP, chamadas de método ou SD) ainda não foi medida.
- **Quadros de ataque fora de TCP/UDP:** no DoS e no *MITM* com um atacante, parte dos quadros do
  atacante não é IPv4 com TCP ou UDP (68.271 e 135.293 quadros, respectivamente). O tipo desses
  quadros ainda não foi caracterizado.

## Como gerar de novo

O gerador faz parte da bancada `someip-testbench` (ECUs em C++ sobre vSomeIP, ponte do CARLA,
atacantes e scripts), que **ainda não está publicada**. Os comandos abaixo valem para quem tiver
acesso a ela; a versão usada está registrada em `PROCEDENCIA.txt`.

Requisitos: Linux com Docker, GPU NVIDIA para o CARLA 0.9.15 e a imagem da bancada com vSomeIP
3.5.6. A geração das sete capturas leva cerca de 3 horas (25 min por captura, mais a subida).

```bash
bash carla/infra/subir.sh      # sobe o servidor do CARLA
GIT_REV=$(git rev-parse --short HEAD) nohup bash platform/carla-live/gera_gama.sh > ~/gama.out 2>&1 &
```

As variáveis `CAPTURAS="..."` (gera só algumas), `DUR` (duração), `RENDER`, `FUZZ2_LAG` (fase da
oferta do *Fuzzy* 2) e `GAMA` (diretório de saída) ajustam a geração.

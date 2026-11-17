# Tráfego SOME/IP gerado com o conteúdo do dataset de referência (veículo parado): experimento de controle

> **Neste repositório** os arquivos grandes estão comprimidos e no Git LFS (`scn.pcap.gz`,
> `scn.labels.gz`). Para usar: `git lfs pull && bash data/parado/prepara.sh`, que descomprime e
> confere o SHA-256 (`data/parado/SHA256SUMS`). Os logs da geração não foram versionados.

Capturas de pacotes da **mesma rede e dos mesmos ataques** do dataset gerado com o CARLA
(`data/gama/v1/`, chamado γ na avaliação), com **uma única diferença**: os valores que as ECUs
provedoras publicam vêm do benigno do dataset de referência de Kim (*SOME/IP traffic (Benign and
Attack samples)*, figshare, DOI [10.6084/m9.figshare.30970450](https://doi.org/10.6084/m9.figshare.30970450),
CC BY 4.0), em que o veículo está praticamente parado, e não de um veículo andando no CARLA.

| | |
|---|---|
| Pasta neste repositório | `data/parado/v1/` |
| Capturas | 7 (1 normal, 6 com ataque), 1.500 s cada |
| Quadros | 16.073.487 no total |
| Formato | PCAP clássico (Ethernet), rótulo por quadro em texto |
| Gerado em | 17/11/2026, por `platform/scenario-live/gera_parado.sh` (bancada `someip-testbench`, commit `3d7ba01`) |
| Licença | a definir |

## Para que serve

Entre o dataset de referência e o dataset γ mudam duas coisas ao mesmo tempo: **quem gera o
tráfego** (a rede do autor ou a nossa bancada) e **o que as mensagens carregam** (veículo parado
ou andando). Este dataset fica no meio do caminho e permite mudar uma coisa de cada vez:

| Comparação | O que muda | O que responde |
|---|---|---|
| referência → este dataset | só o gerador | a bancada reproduz o gerador da referência? |
| este dataset → γ | só o conteúdo (parado → andando) | a dinâmica do veículo, sozinha, muda o tráfego para o detector? |

Os resultados estão em `experiments/cross-domain/` (README e `resultados/`).

## Como o tráfego é produzido

Igual ao do γ (`data/gama/v1/README.md`, seção "Como o tráfego é produzido"), trocando o CARLA por
um **banco de *payloads***:

1. O banco é extraído uma vez do `benign_traffic.pcap` da referência (`tools/extract_payloads.py`):
   para cada um dos 11 eventos dos três serviços (VDE 0x1001, IMU 0x1002, GPS 0x1003), a sequência
   de *payloads* de notificação, **na ordem** em que aparecem (1,09 milhão de notificações; md5 do
   banco em `PROCEDENCIA.txt`).
2. Cada ECU provedora publica a amostra seguinte do banco a cada ciclo do evento. A ordem importa,
   porque várias *features* comparam um pacote com o anterior.
3. Todo o resto é da bancada, como no γ: as nove ECUs (vSomeIP 3.5.6), o Service Discovery, as
   assinaturas, as chamadas de método (a resposta traz os valores publicados por último), os
   atacantes e a captura.

Os *payloads* publicados pelos atacantes são os mesmos do γ (também tirados da referência).

## Diferenças em relação ao γ

| Diferença | Motivo |
|---|---|
| O conteúdo dos sinais | É o objetivo: os valores do benigno da referência (veículo parado), não os do CARLA |
| O banco volta ao início perto do fim da captura | A referência tem menos amostras do que a bancada publica em 1.500 s, porque a taxa da VDE cai ao longo do arquivo dela. O evento 0x0002 da VDE (5,1 ms) volta ao início por volta dos 1.040 s; o 0x0001 (10,1 ms), por volta dos 1.300 s |
| Uma sub-rede por captura | As capturas foram geradas em quatro rodadas paralelas na mesma máquina, cada uma na sua rede Docker: 172.28 (benign, fuzzy1), 172.30 (dos, fuzzy2), 172.32 (fuzzy3, mitm_single) e 172.34 (mitm_multi). O último byte de cada IP é o mesmo do γ; os MACs mudam junto com a sub-rede e estão em `injector.mac`. Nenhuma *feature* usa o endereço |
| Não há `viagem.csv` | Não há viagem: não há CARLA |

As assinaturas foram conferidas contra a referência e o γ (TCP no benigno 99,11%; DoS 49,8 ofertas
falsas por segundo; MITM com um atacante, 99,9 ofertas por segundo; MITM com dois atacantes,
163.339 retiradas com o IP da VDE forjado, contra 163.188 na referência). Um teste com quatro
rodadas paralelas de 120 s antes da geração confirmou que o paralelismo não altera essas assinaturas.

## Arquivos

Em cada uma das sete pastas (`benign`, `dos`, `fuzzy1`, `fuzzy2`, `fuzzy3`, `mitm_single`,
`mitm_multi`): `scn.pcap.gz`, `scn.labels.gz`, `injector.mac`, `linha-do-tempo.txt` e `rotulo.txt`,
com o mesmo formato e as mesmas classes do γ (`data/gama/v1/README.md`, seções "Rótulos" e
"Arquivos"). Na raiz de `v1/`: `PROCEDENCIA.txt` e `RESUMO.txt`.

## Composição

| Captura | Quadros | Ataque (quadros) | Pacotes IPv4 TCP/UDP | Normais | Ataque |
|---|---:|---:|---:|---:|---:|
| benign | 2.498.673 | 0 | 2.497.692 | 2.497.692 | 0 |
| dos | 2.033.554 | 386.291 | 1.963.362 | 1.646.002 | 317.360 |
| fuzzy1 | 2.521.260 | 5.270 | 2.520.179 | 2.514.915 | 5.264 |
| fuzzy2 | 1.404.604 | 47.599 | 1.403.201 | 1.355.612 | 47.589 |
| fuzzy3 | 2.498.306 | 606.221 | 2.497.309 | 1.891.262 | 606.047 |
| mitm_single | 2.536.999 | 615.073 | 2.399.834 | 1.920.770 | 479.064 |
| mitm_multi | 2.580.091 | 604.931 | 2.578.838 | 1.974.251 | 604.587 |
| **Total** | **16.073.487** | **2.265.385** | **15.860.415** | **13.800.504** | **2.059.911** |

Os volumes de ataque ficam próximos dos do γ (por exemplo, MITM com um atacante: 479.064 pacotes,
contra 476.925 no γ e 360.510 na referência), o que indica que a diferença de volume nessa classe é
da bancada, e não do conteúdo.

## Como gerar de novo

Na bancada `someip-testbench` (ainda não publicada), com Docker e a imagem `someip-base:3.5.6`. Uma
cópia do repositório por rodada paralela; o banco é gerado uma vez e copiado para cada cópia:

```bash
python tools/extract_payloads.py --repro <repo-de-reproducao> --pcap benign_traffic.pcap \
    --out build/cfg/payloads-kim.bin --limite 1000000
SLOT=0 CAPTURAS="benign fuzzy1" SAIDA=~/parado/v1 BANCO=build/cfg/payloads-kim.bin \
    nohup bash platform/scenario-live/gera_parado.sh > ~/parado-s0.out 2>&1 &
```

Com quatro rodadas paralelas (SLOT 0 a 3) numa máquina de 8 vCPU, as sete capturas levam ~55 min.

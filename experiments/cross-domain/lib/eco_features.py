"""Feature de eco: a origem está republicando o que acabou de receber? (MITM multi, docs/ataques-kim.md)

Mecanismo do ataque, na descrição do próprio autor do dataset: o retransmissor assina o fluxo
legítimo e republica "a byte identical copy" do payload num serviço próprio. Pacote a pacote, isso é
indistinguível de uma ECU normal (valores reais, ritmo regular); o que o denuncia é a RELAÇÃO entre o
que a origem recebe e o que ela publica.

Definição, fixada pelo mecanismo antes de qualquer treino (e não ajustada aos números):

  eco        1 se o payload desta notificação é IDÊNTICO, byte a byte, a um payload que a MESMA
             origem recebeu (como destino) de outra origem nos últimos JANELA_ECO segundos; senão 0.
  eco_frac   fração das notificações desta origem, no último JANELA_FRAC segundo, que foram eco.
             Vale também para os pacotes dela que não são notificação (ACKs, SD): leva o contexto
             da origem a todos os pacotes dela.

Por que "recebeu" e não "qualquer outra origem publicou": num carro (e no perfil sintético
'constante' da bancada) ECUs diferentes podem publicar o mesmo payload por coincidência, inclusive
só zeros; o que caracteriza o repasse é publicar o que se acabou de RECEBER. As ECUs que publicam
dados no barramento do Kim não recebem dados de ninguém. Limitação conhecida: um gateway legítimo,
que repassa sinais de um barramento para outro, também faz isso, e teria de estar declarado.
"""
from collections import defaultdict, deque

ECO_NOMES = ["eco", "eco_frac"]
JANELA_ECO = 0.1
JANELA_FRAC = 1.0
NOTIFICACAO = 0x02


class EcoStreamer:
    def __init__(self):
        self.recebidos = defaultdict(dict)   # ip -> {payload: instante em que o recebeu}
        self.fila = deque()                  # (instante, ip destino, payload), para expirar
        self.hist = defaultdict(deque)       # ip origem -> (instante, eco) das notificações dela

    def _frac(self, src, ts):
        h = self.hist[src]
        while h and ts - h[0][0] > JANELA_FRAC:
            h.popleft()
        return (sum(e for _, e in h) / len(h)) if h else 0.0

    def step(self, p):
        ts = p.ts
        while self.fila and ts - self.fila[0][0] > JANELA_ECO:
            t0, d0, pl0 = self.fila.popleft()
            r = self.recebidos.get(d0)
            if r is not None and r.get(pl0) == t0:
                del r[pl0]
        pl = p.pl_someip
        if not getattr(p, "is_someip", False) or getattr(p, "is_sd", False) or not pl or p.msg_type != NOTIFICACAO:
            return (0.0, self._frac(p.src, ts))
        eco = 1.0 if pl in self.recebidos.get(p.src, ()) else 0.0
        self.recebidos[p.dst][pl] = ts
        self.fila.append((ts, p.dst, pl))
        self.hist[p.src].append((ts, eco))
        return (eco, self._frac(p.src, ts))

"""Modelo de bytes posicional (Eq. 2-6 do artigo Kim et al., 2026).

Aprende, a partir de payloads BENIGNOS de um tipo (SOME/IP, SD ou TCP/UDP), a distribuição
de bytes por posição com suavização de Laplace, e fornece:
  - log-verossimilhança  logL(x) = sum_i log P_i(x_i)            (Eq. 5)
  - entropia cruzada     H(x;P)  = -(1/L) sum_i log P_i(x_i)     (Eq. 6)

Escolhas de implementação (documentadas, pois o artigo não fixa os valores):
  - L (comprimento fixo): truncamos o payload em L bytes; payloads mais curtos contribuem
    apenas com as posições existentes (sem símbolo de padding artificial).
  - alpha (Laplace): padrão 1.0.
  - Normalização posicional sobre 256 valores de byte (Eq. 3).
"""
from __future__ import annotations

import numpy as np


class ByteModel:
    def __init__(self, L: int, alpha: float = 1.0):
        self.L = int(L)
        self.alpha = float(alpha)
        self._counts = np.zeros((self.L, 256), dtype=np.float64)
        self.logP: np.ndarray | None = None

    # ---- treino ----
    def update(self, payload: bytes) -> None:
        """Acumula contagens posicionais de um payload benigno."""
        k = min(len(payload), self.L)
        if k == 0:
            return
        arr = np.frombuffer(payload[:k], dtype=np.uint8)
        self._counts[np.arange(k), arr] += 1.0

    def finalize(self) -> "ByteModel":
        """Calcula P_i(b) com Laplace (Eq. 3) e guarda log P."""
        P = (self._counts + self.alpha) / (
            self._counts.sum(axis=1, keepdims=True) + self.alpha * 256.0
        )
        self.logP = np.log(P)
        return self

    # ---- inferência ----
    def loglik(self, payload: bytes) -> float:
        """logL(x) somada nas posições disponíveis (Eq. 5). 0.0 se payload vazio."""
        if self.logP is None:
            raise RuntimeError("ByteModel não finalizado")
        k = min(len(payload), self.L)
        if k == 0:
            return 0.0
        arr = np.frombuffer(payload[:k], dtype=np.uint8)
        return float(self.logP[np.arange(k), arr].sum())

    def cross_entropy(self, payload: bytes) -> float:
        """H(x;P) = -(1/L) sum log P_i(x_i) (Eq. 6). 0.0 se payload vazio."""
        if self.logP is None:
            raise RuntimeError("ByteModel não finalizado")
        k = min(len(payload), self.L)
        if k == 0:
            return 0.0
        arr = np.frombuffer(payload[:k], dtype=np.uint8)
        return float(-self.logP[np.arange(k), arr].sum() / k)


def hamming(a: bytes, b: bytes) -> int:
    """Distância de Hamming em nível de byte entre dois payloads (Eq. 7).

    Conta posições com bytes diferentes no comprimento comum + diferença de comprimento
    (bytes presentes em um e ausentes no outro contam como mudança).
    """
    if not a and not b:
        return 0
    n = min(len(a), len(b))
    if n == 0:
        return max(len(a), len(b))
    aa = np.frombuffer(a[:n], dtype=np.uint8)
    bb = np.frombuffer(b[:n], dtype=np.uint8)
    return int(np.count_nonzero(aa != bb) + abs(len(a) - len(b)))

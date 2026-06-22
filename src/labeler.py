"""Rotulador por-pacote das assinaturas de ataque do dataset Kim.

⚠️ Princípio (ver docs/analise-pcaps.md): os PCAPs de ataque contêm tráfego benigno de
fundo. Cada pacote é rotulado pela assinatura do **cenário daquele arquivo**; pacotes que
não casam a assinatura ficam como benignos (0), mesmo dentro de um arquivo de ataque.

Cada arquivo é um cenário conhecido, então o **tipo** (multiclasse) vem do arquivo; a
**assinatura por-pacote** decide quais pacotes daquele arquivo são realmente o ataque.

Assinaturas (validadas contra os PCAPs):
  - DoS         : notificação ADAS (svc 0x1001, method 0x0001) dentro de uma rajada de alta
                  taxa no mesmo fluxo (flood). Requer estado temporal -> ver extract.py.
  - FUZZY       : SD OfferService anunciando service_id fora do conjunto legítimo
                  {0x1001,0x1002,0x1003} (flood de identificadores aleatórios).
                  (Limitação: as notificações ADAS de payload aleatório (B) não são
                  rotuladas por assinatura estática; ver docs/analise-pcaps.md.)
  - MITM-single : SD withdraw (OfferService com TTL=0 para serviço legítimo).
  - MITM-multi  : serviço de relay 0x100B  OU  SD withdraw (TTL=0).
                  (Injeção ADAS forjada byte-idêntica ao benigno não é separável por assinatura.)
"""
from __future__ import annotations

from someip import Pkt, SD_OFFER, MT_NOTIFICATION

# rótulos multiclasse
NORMAL = 0
DOS = 1
FUZZY = 2
MITM_SINGLE = 3
MITM_MULTI = 4

NAMES = {NORMAL: "normal", DOS: "dos", FUZZY: "fuzzy",
         MITM_SINGLE: "mitm_single", MITM_MULTI: "mitm_multi"}

LEGIT_SERVICES = {0x1001, 0x1002, 0x1003}
ADAS_SERVICE = 0x1001
RELAY_SERVICE = 0x100B


def is_adas_notification(p: Pkt) -> bool:
    return (p.service_id == ADAS_SERVICE and p.method_id == 0x0001
            and p.msg_type == MT_NOTIFICATION)


def _has_withdraw(p: Pkt) -> bool:
    """SD OfferService com TTL=0 para serviço legítimo (stopOffer / spoofing)."""
    for (etype, sid, iid, ttl) in p.sd_entries:
        if etype == SD_OFFER and ttl == 0 and sid in LEGIT_SERVICES:
            return True
    return False


def _has_fuzzy_offer(p: Pkt) -> bool:
    """SD OfferService anunciando serviço fora do conjunto legítimo."""
    for (etype, sid, iid, ttl) in p.sd_entries:
        if etype == SD_OFFER and ttl != 0 and sid not in LEGIT_SERVICES:
            return True
    return False


def sig_fuzzy(p: Pkt) -> bool:
    return _has_fuzzy_offer(p)


def sig_mitm_single(p: Pkt) -> bool:
    return _has_withdraw(p)


def sig_mitm_multi(p: Pkt) -> bool:
    return p.service_id == RELAY_SERVICE or _has_withdraw(p)


# assinaturas estáticas por tipo (DoS é tratado por taxa no extractor)
STATIC_SIG = {
    FUZZY: sig_fuzzy,
    MITM_SINGLE: sig_mitm_single,
    MITM_MULTI: sig_mitm_multi,
}

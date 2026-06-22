"""Parser SOME/IP / SOME/IP-SD a partir de bytes crus de pacote (Ethernet/IP/UDP/TCP).

Projetado para velocidade: opera sobre os bytes crus entregues por
`scapy.utils.RawPcapReader`, sem dissecação completa do scapy.

Cabeçalho SOME/IP (16 bytes):
    service_id(2) method_id(2) length(4) client_id(2) session_id(2)
    protocol_version(1) interface_version(1) message_type(1) return_code(1)
Payload SOME/IP = bytes após os 16 do cabeçalho.

Para SOME/IP-SD (porta UDP 30490), o payload SD é:
    flags(1) reserved(3) len_entries(4) [entries...] len_options(4) [options...]
Cada entry tem 16 bytes; para Offer/Find (type 0x00/0x01):
    type(1) idx1(1) idx2(1) n_opt(1) service_id(2) instance_id(2)
    major(1) ttl(3) minor(4)
TTL == 0 em OfferService => withdraw / stopOffer.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field

SD_PORT = 30490
ETH_IPV4 = b"\x08\x00"

# message_type
MT_NOTIFICATION = 0x02
# SD entry types
SD_FIND = 0x00
SD_OFFER = 0x01


def _ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


@dataclass(slots=True)
class Pkt:
    ts: float = 0.0
    src: str = ""
    dst: str = ""
    proto: int = 0          # 6=TCP, 17=UDP
    sport: int = 0
    dport: int = 0
    ip_len: int = 0         # tamanho total do datagrama IP
    is_someip: bool = False
    is_sd: bool = False
    service_id: int = -1
    method_id: int = -1
    msg_type: int = -1
    client_id: int = -1
    # payloads (memoryview/bytes)
    pl_l4: bytes = b""      # payload de transporte (após TCP/UDP), inclui header SOME/IP
    pl_someip: bytes = b""  # payload da aplicação SOME/IP (após os 16 bytes), se não-SD
    pl_sd: bytes = b""      # payload SD (após os 16 bytes), se SD
    # entradas SD (apenas quando is_sd): lista de (type, service_id, instance_id, ttl)
    sd_entries: tuple = field(default_factory=tuple)


def parse(raw: bytes, ts: float = 0.0) -> Pkt | None:
    """Faz o parse de um frame Ethernet cru. Retorna Pkt ou None se não for IPv4/TCP/UDP."""
    if raw[12:14] != ETH_IPV4:
        return None
    ihl = (raw[14] & 0x0F) * 4
    proto = raw[23]
    ip_len = int.from_bytes(raw[16:18], "big")
    l4 = 14 + ihl
    p = Pkt(ts=ts, src=_ip(raw[26:30]), dst=_ip(raw[30:34]), proto=proto, ip_len=ip_len)

    if proto == 17:        # UDP
        p.sport = int.from_bytes(raw[l4:l4 + 2], "big")
        p.dport = int.from_bytes(raw[l4 + 2:l4 + 4], "big")
        off = l4 + 8
    elif proto == 6:       # TCP
        p.sport = int.from_bytes(raw[l4:l4 + 2], "big")
        p.dport = int.from_bytes(raw[l4 + 2:l4 + 4], "big")
        doff = (raw[l4 + 12] >> 4) * 4
        off = l4 + doff
    else:
        return None

    p.pl_l4 = raw[off:]
    if len(p.pl_l4) < 16:
        return p           # sem cabeçalho SOME/IP completo; ainda conta como TCP/UDP

    # cabeçalho SOME/IP
    p.service_id = int.from_bytes(p.pl_l4[0:2], "big")
    p.method_id = int.from_bytes(p.pl_l4[2:4], "big")
    p.client_id = int.from_bytes(p.pl_l4[8:10], "big")  # request_id = client_id(2)+session_id(2)
    p.msg_type = p.pl_l4[14]
    p.is_someip = True
    body = p.pl_l4[16:]

    if p.dport == SD_PORT or p.sport == SD_PORT or p.service_id == 0xFFFF:
        p.is_sd = True
        p.pl_sd = body
        p.sd_entries = _parse_sd_entries(body)
    else:
        p.pl_someip = body
    return p


def _parse_sd_entries(body: bytes) -> tuple:
    """Extrai entradas SD: tupla de (type, service_id, instance_id, ttl)."""
    if len(body) < 12:
        return ()
    try:
        len_entries = int.from_bytes(body[4:8], "big")
        start = 8
        end = start + len_entries
        entries = []
        i = start
        while i + 16 <= min(end, len(body)):
            etype = body[i]
            sid = int.from_bytes(body[i + 4:i + 6], "big")
            iid = int.from_bytes(body[i + 6:i + 8], "big")
            ttl = int.from_bytes(body[i + 9:i + 12], "big")
            entries.append((etype, sid, iid, ttl))
            i += 16
        return tuple(entries)
    except Exception:
        return ()


def flow_key(p: Pkt) -> tuple:
    """Chave de fluxo: mesmo par IP + portas (direcional, como no artigo)."""
    return (p.src, p.dst, p.sport, p.dport, p.proto)

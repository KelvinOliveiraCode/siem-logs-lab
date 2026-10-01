"""Gerador dos logs sinteticos.

Gera `dados/logs-sinteticos.jsonl` com semente fixa.

Deterministic generator for `dados/logs-sinteticos.jsonl`.

O arquivo tem 7 padroes de ataque plantados e uma massa de trafego normal.
O trafego normal existe para provar o **teste negativo**: se as 7 regras
disparam em trafego limpo, elas nao sao regras - sao ruido.

Os 7 padroes:

1. ``multiplos_logins_falhados``  - 3+ falhas do mesmo IP em 60s
2. ``login_sucesso_apos_falhas``   - sucesso logo depois das falhas
3. ``acesso_fora_horario``         - login entre 00h e 05h
4. ``conta_privilegio_usuario_comum`` - conta privilegiada em login comum
5. ``download_volume_anormal``     - transferencia muito acima do perfil
6. ``conexao_saida_bloqueio``      - destino em lista de bloqueio
7. ``enumeracao_recursos``         - muitos recursos distintos em curto intervalo
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

#: Semente fixa. Mesmo valor, mesmo arquivo, sempre.
SEMENTE = 20260901

#: Inicio da serie (UTC).
INICIO = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)

#: IPs de origem benignos.
IPS_NORMAIS = [f"10.0.0.{i}" for i in range(10, 200)]

#: IPs de origem dos ataques.
IPS_ATAQUE = [f"10.99.0.{i}" for i in range(1, 9)]

#: Destinos bloqueados.
DESTINOS_BLOQUEADOS = ["203.0.113.45", "198.51.100.77", "203.0.113.200"]

#: Tipos de evento de trafego normal.
#: `acesso_recurso` NAO entra aqui: o trafego normal usa `acesso_sistema`.
#: Enumeracao usa `enum_recurso`, que e o que separa ataque de uso normal.
TIPOS_NORMAIS = ["login_sucesso", "acesso_sistema", "acao_sistema"]

#: Faixa horaria de trabalho.
HORA_TRABALHO = range(6, 22)


def _iso(dt: datetime) -> str:
    """Formata no ISO 8601 com Z.

    Format as ISO 8601 with Z.
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def gerar(destino: str, total_normal: int = 2300) -> list[dict]:
    """Gera a serie completa de eventos.

    Generate the full event series.

    Args:
        destino: Caminho do ``.jsonl`` a gravar.
        total_normal: Quantos eventos de trafego normal gerar.

    Returns:
        Lista de eventos, ja gravada em ``destino``.
    """
    rng = random.Random(SEMENTE)
    eventos: list[dict] = []
    t = INICIO

    def avanca() -> None:
        nonlocal t
        t = t + timedelta(seconds=rng.randint(1, 20))

    def normal() -> dict:
        hora = rng.choice(list(HORA_TRABALHO))
        when = t.replace(hour=hora, minute=rng.randint(0, 59))
        return {
            "timestamp": _iso(when),
            "origem_ip": rng.choice(IPS_NORMAIS),
            "tipo_evento": rng.choice(TIPOS_NORMAIS),
            "usuario": f"user_{rng.randint(1, 60)}",
            "recurso": f"/app/recurso_{rng.randint(1, 40)}",
            "bytes": rng.randint(1000, 900_000),
            "fora_horario": False,
            "conta_privilegiada": False,
            "destino_bloqueado": False,
        }

    # --- Padrao 1 e 2: forca bruta seguida de sucesso (2 IPs) ---
    for n, ip in enumerate(IPS_ATAQUE[:2]):
        for k in range(6):
            avanca()
            eventos.append({
                "timestamp": _iso(t),
                "origem_ip": ip,
                "tipo_evento": "login_falhido",
                "usuario": "admin",
                "recurso": "",
                "bytes": 0,
                "fora_horario": False,
                "conta_privilegiada": False,
                "destino_bloqueado": False,
            })
        avanca()
        eventos.append({
            "timestamp": _iso(t),
            "origem_ip": ip,
            "tipo_evento": "login_sucesso",
            "usuario": "admin",
            "recurso": "",
            "bytes": 0,
            "fora_horario": False,
            "conta_privilegiada": True,
            "destino_bloqueado": False,
            "padrao": f"forca_bruta_{n + 1}",
        })

    # --- Padrao 3: acesso fora do horario (1 IP) ---
    for _ in range(4):
        avanca()
        madruga = t.replace(hour=rng.randint(0, 4), minute=rng.randint(0, 59))
        eventos.append({
            "timestamp": _iso(madruga),
            "origem_ip": IPS_ATAQUE[2],
            "tipo_evento": "login_sucesso",
            "usuario": "user_7",
            "recurso": "",
            "bytes": 0,
            "fora_horario": True,
            "conta_privilegiada": False,
            "destino_bloqueado": False,
        })

    # --- Padrao 4: conta de privilegio por usuario comum (IP de ataque) ---
    for _ in range(5):
        avanca()
        evento = normal()
        evento["conta_privilegiada"] = True
        evento["usuario"] = f"user_{rng.randint(1, 60)}"
        evento["origem_ip"] = IPS_ATAQUE[7]
        eventos.append(evento)

    # --- Padrao 5: download de volume anormal (1 IP) ---
    for _ in range(4):
        avanca()
        evento = normal()
        evento["tipo_evento"] = "download"
        evento["bytes"] = rng.randint(180_000_000, 900_000_000)
        evento["origem_ip"] = IPS_ATAQUE[3]
        eventos.append(evento)

    # --- Padrao 6: conexao para destino bloqueado (2 IPs) ---
    for ip in (IPS_ATAQUE[4], IPS_ATAQUE[5]):
        for _ in range(3):
            avanca()
            eventos.append({
                "timestamp": _iso(t),
                "origem_ip": ip,
                "tipo_evento": "conexao_saida",
                "usuario": f"user_{rng.randint(1, 60)}",
                "recurso": rng.choice(DESTINOS_BLOQUEADOS),
                "bytes": 0,
                "destino_bloqueado": True,
                "fora_horario": False,
                "conta_privilegiada": False,
            })

    # --- Padrao 7: enumeracao de recursos (1 IP, muitos recursos) ---
    for k in range(45):
        avanca()
        eventos.append({
            "timestamp": _iso(t),
            "origem_ip": IPS_ATAQUE[6],
            "tipo_evento": "enum_recurso",
            "usuario": "scanner",
            "recurso": f"/recurso_enumerado_{k}",
            "bytes": 0,
            "fora_horario": False,
            "conta_privilegiada": False,
            "destino_bloqueado": False,
        })

    # --- Trafego normal, espalhado ao longo dos 30 dias ---
    for _ in range(total_normal):
        avanca()
        dia = t.day - 1
        evento = normal()
        when = t.replace(hour=rng.choice(list(HORA_TRABALHO)), minute=rng.randint(0, 59))
        evento["timestamp"] = _iso(when + timedelta(days=min(dia, 29)))
        eventos.append(evento)

    eventos.sort(key=lambda e: e["timestamp"])

    with open(destino, "w", encoding="utf-8", newline="\n") as fh:
        for e in eventos:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    return eventos


if __name__ == "__main__":
    import sys

    alvo = sys.argv[1] if len(sys.argv) > 1 else "dados/logs-sinteticos.jsonl"
    gerados = gerar(alvo)
    print(f"{len(gerados)} eventos gravados em {alvo}")
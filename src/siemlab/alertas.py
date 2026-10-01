"""Módulo de geração de alertas MITRE ATT&CK."""

import json
from collections import defaultdict
from datetime import datetime, timezone


def gerar_alerta_mitre(tipo: str, detalhes: dict) -> dict:
    """Gerar alerta no formato MITRE ATT&CK."""
    mapa_technique = {
        "multiplos_logins_falhados": "T1110",  # Brute Force
        "login_sucesso_apos_falhas": "T1078",  # Valid Accounts
        "acesso_fora_horario": "T1078",  # Valid Accounts / T1090
        "conta_privilegio_usuario_comum": "T1078",  # Valid Accounts
        "download_volume_anormal": "T1005",  # Data Staged
        "conexao_saida_bloqueio": "T1071",  # Application Layer Protocol
        "enumeracao_recursos": "T1087",  # Account Discovery
    }

    technique = mapa_technique.get(tipo, "T1000")
    
    alerta = {
        "id_alerta": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "tecnica_mitre": technique,
        "titulo": f"[{technique}] {tipo.replace('_', ' ').title()}",
        "severidade": "media",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tipo": tipo,
        "entidades": detalhes,
    }

    # Definir severidade baseada no tipo
    severidades = {
        "multiplos_logins_falhados": "alta",
        "conta_privilegio_usuario_comum": "alta",
        "download_volume_anormal": "alta",
        "conexao_saida_bloqueio": "alta",
        "acesso_fora_horario": "media",
        "enumeracao_recursos": "media",
        "login_sucesso_apos_falhas": "alta",
    }
    if tipo in severidades:
        alerta["severidade"] = severidades[tipo]

    return alerta


def agrupar_alertas(alertas: list) -> dict:
    """Agrupar alertas por técnica MITRE."""
    agrupados = defaultdict(list)
    for alerta in alertas:
        tecnica = alerta.get("tecnica_mitre", "Desconhecido")
        agrupados[tecnica].append(alerta)
    return dict(agrupados)


def gerar_relatorio_alertas(alertas: list) -> str:
    """Gerar relatório em JSON com todos os alertas."""
    relatorio = {
        "gerado_em": datetime.now(timezone.utc).isoformat(),
        "total_alertas": len(alertas),
        "alertas": alertas,
    }
    return json.dumps(relatorio, indent=2, ensure_ascii=False)
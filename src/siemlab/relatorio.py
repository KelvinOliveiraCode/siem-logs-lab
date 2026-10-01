"""Módulo de geração de relatórios SIEM."""

import json
import datetime


def gerar_relatorio_json(alertas: list, eventos_processados: int) -> str:
    """Gerar relatório em formato JSON."""
    relatorio = {
        "metadado": {
            "gerado_em": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "eventos_processados": eventos_processados,
            "total_alertas": len(alertas),
        },
        "alertas": alertas,
    }
    return json.dumps(relatorio, indent=2, ensure_ascii=False)


def gerar_relatorio_resumo(alertas: list) -> str:
    """Gerar resumo dos alertas por severidade e técnica."""
    contagem_por_severidade = {}
    contagem_por_technique = {}

    for alerta in alertas:
        severidade = alerta.get("severidade", "media")
        tecnica = alerta.get("tecnica_mitre", "Desconhecido")

        contagem_por_severidade[severidade] = contagem_por_severidade.get(severidade, 0) + 1
        contagem_por_technique[tecnica] = contagem_por_technique.get(tecnica, 0) + 1

    resumo = {
        "total_alertas": len(alertas),
        "por_severidade": contagem_por_severidade,
        "por_technique": contagem_por_technique,
    }
    return json.dumps(resumo, indent=2, ensure_ascii=False)
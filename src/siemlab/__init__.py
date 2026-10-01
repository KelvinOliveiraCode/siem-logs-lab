"""siemlab - pipeline local de SIEM.

Coleta logs JSONL, normaliza, aplica regras de deteccao, correlaciona eventos
em janela temporal e emite alertas mapeados no MITRE ATT&CK. Tudo local, sem
servico externo e sem custo.

Local SIEM pipeline: reads JSONL logs, normalises, applies detection rules,
correlates events in a sliding time window, and emits MITRE ATT&CK alerts.
Entirely local, no external service, no cost.
"""

from .alertas import agrupar_alertas, gerar_alerta_mitre
from .correlacao import (
    AgrupamentoPorIP,
    JanelaTemporal,
    correlacionar_acesso_horario_insolito,
    correlacionar_enumeracao_recursos,
    correlacionar_logins_falhados,
)
from .normalizador import normalizar_evento, normalizar_ip, normalizar_timestamp
from .regras import RegraSigma, avaliar_regra, carregar_regra_yaml, carregar_regras

__all__ = [
    "gerar_alerta_mitre",
    "agrupar_alertas",
    "JanelaTemporal",
    "AgrupamentoPorIP",
    "correlacionar_logins_falhados",
    "correlacionar_acesso_horario_insolito",
    "correlacionar_enumeracao_recursos",
    "normalizar_evento",
    "normalizar_ip",
    "normalizar_timestamp",
    "RegraSigma",
    "avaliar_regra",
    "carregar_regra_yaml",
    "carregar_regras",
]

__version__ = "1.0.0"
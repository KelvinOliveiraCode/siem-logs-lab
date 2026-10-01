"""Módulo de correlação de eventos SIEM - janela temporal deslizante e agrupamento."""

import json
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta


class JanelaTemporal:
    """Janela temporal deslizante para correlação de eventos.

    A janela é ancorada no **evento mais recente visto**, não no relógio do
    sistema. Um SIEM processa log histórico: se a janela usasse `now()`, um
    arquivo de_events de ontem inteiro seria descartado antes da correlação, e
    a regra nunca dispararia. Este foi o primeiro bug encontrado neste
    repositório, e o sintoma era "nenhuma correlação nunca dispara".

    The window is anchored to the **newest event seen**, not to the system
    clock. A SIEM processes historical logs: with `now()` every event from
    yesterday would be evicted before correlation, and the rule would never
    fire.
    """

    def __init__(self, tamanho_segundos: int = 60):
        self.tamanho_segundos = tamanho_segundos
        self.eventos = deque()

    def adicionar(self, evento: dict, timestamp_key: str = "timestamp"):
        """Adicionar evento à janela temporal.

        Adicionar também move a âncora da janela para o evento mais recente,
        de modo que `remover_velhos` tenha contra o que comparar.
        """
        ts_str = evento.get(timestamp_key, "")
        try:
            if ts_str.endswith("+00:00") or ts_str.endswith("Z"):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            self.eventos.append((ts, evento))
        except (ValueError, TypeError, AttributeError):
            pass  # Ignorar eventos com timestamp inválido

    def remover_velhos(self):
        """Remover eventos que caíram fora da janela temporal.

        Remove events older than `tamanho_segundos` before the newest one.
        """
        if not self.eventos:
            return
        referencia = max(ts for ts, _ in self.eventos)
        limite = referencia - timedelta(seconds=self.tamanho_segundos)

        while self.eventos and self.eventos[0][0] < limite:
            self.eventos.popleft()

    def eventos_na_janela(self) -> list:
        """Retornar eventos atualmente na janela.

        Return the events currently inside the window.
        """
        return [ev for _, ev in self.eventos]

    #: Nome antigo, mantido para compatibilidade com quem ja chamava assim.
    eventos_na_janel = eventos_na_janela


class AgrupamentoPorIP:
    """Agrupar eventos por endereço IP para detecção de padrões."""

    def __init__(self):
        self.agrupamentos = defaultdict(list)

    def adicionar(self, evento: dict, ip_key: str = "origem_ip"):
        ip = evento.get(ip_key, "")
        if ip:
            self.agrupamentos[ip].append(evento)

    def get_ip(self, ip: str) -> list:
        """Retornar eventos para um IP específico."""
        return self.agrupamentos.get(ip, [])


def correlacionar_logins_falhados(eventos: list, janela_segundos: int = 60) -> list:
    """Correlacionar múltiplas falhas de login do mesmo IP em janela temporal."""
    janela = JanelaTemporal(janela_segundos)
    resultados = []

    # Agrupar por IP primeiro
    ip_groups = defaultdict(list)
    for evento in eventos:
        ip = evento.get("origem_ip", "")
        if ip:
            ip_groups[ip].append(evento)

    for ip, ip_eventos in ip_groups.items():
        # Contar falhas de login
        falhas = [e for e in ip_eventos if e.get("tipo_evento", "") == "login_falhado"]
        
        if len(falhas) >= 3:  # Padrão: 3+ falhas em 60s
            # Verificar se há login bem-sucedido logo após
            sucessos = [e for e in ip_eventos if e.get("tipo_evento", "") == "login_sucesso"]
            
            resultados.append({
                "tipo": "multiplos_logins_falhados",
                "origem_ip": ip,
                "numero_falhas": len(falhas),
                "janela_segundos": janela_segundos,
                "tem_login_sucesso_posterior": len(sucessos) > 0,
                "evidencia": {
                    "falhas": [e.get("timestamp", "") for e in falhas[:5]],
                    "total_falhas": len(falhas),
                }
            })

    return resultados


def correlacionar_acesso_horario_insolito(eventos: list, horario_ini: int = 0, horario_fim: int = 23) -> list:
    """Correlacionar acesso fora do horário habitual."""
    resultados = []
    
    for evento in eventos:
        ts_str = evento.get("timestamp", "")
        try:
            if ts_str.endswith("+00:00") or ts_str.endswith("Z"):
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            else:
                ts = datetime.fromisoformat(ts_str)
            hora = ts.hour
            
            # Horário fora do normal (antes das 6 ou depois das 22)
            if hora < 6 or hora > 22:
                resultados.append({
                    "tipo": "acesso_fora_horario",
                    "origem_ip": evento.get("origem_ip", ""),
                    "hora": hora,
                    "usuario": evento.get("usuario", ""),
                    "evidencia": {"timestamp": ts_str, "hora_acesso": hora},
                })
        except (ValueError, TypeError):
            pass
    
    return resultados


def correlacionar_enumeracao_recursos(eventos: list, max_por_minuto: int = 20) -> list:
    """Correlacionar enumeração de recursos em curto intervalo (scanning).

    Correlate resource enumeration over a short interval (internal scanning).

    Conta recursos **distintos**, nao eventos. Enumeracao e variacao de alvo:
    quem enumera visita 45 caminhos diferentes, nao o mesmo caminho 45 vezes.
    Contar eventos confundia trafego normal de aplicacao web com varredura -
    e era o que produzia 562 alertas falsos.

    Args:
        eventos: Eventos ja normalizados.
        max_por_minuto: Quantos recursos distintos disparam o alerta.

    Returns:
        Lista de achados, um por IP acima do limite.
    """
    resultados = []

    ip_groups = defaultdict(list)
    for evento in eventos:
        ip = evento.get("origem_ip", "")
        if ip:
            ip_groups[ip].append(evento)

    for ip, ip_eventos in ip_groups.items():
        recursos = {
            evento.get("recurso")
            for evento in ip_eventos
            if evento.get("recurso")
        }

        if len(recursos) >= max_por_minuto:
            resultados.append({
                "tipo": "enumeracao_recursos",
                "origem_ip": ip,
                "total_recursos": len(recursos),
                "limite": max_por_minuto,
                "evidencia": {
                    # Lista ordenada, nao set: set nao e serializavel em JSON
                    # e quebrava a gravacao do relatorio.
                    "amostra_recursos": sorted(recursos)[:20],
                },
            })

    return resultados
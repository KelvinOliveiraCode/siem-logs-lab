"""Normalizador de logs SIEM - extrai e padroniza campos de eventos."""

import re
import json
from datetime import datetime, timezone


def normalizar_timestamp(ts_str: str) -> str:
    """Normalizar timestamp de várias formas para ISO 8601."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()

    # Tente diversos formatos
    ts_str = ts_str.strip()

    # Formato ISO com Z
    if ts_str.endswith("Z"):
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except ValueError:
            pass

    # Formato com offset +0000
    if "+0000" in ts_str or "-0000" in ts_str:
        try:
            dt = datetime.fromisoformat(ts_str)
            return dt.isoformat()
        except ValueError:
            pass

    # Formato dd/Mon/yyyy:HH:MM:SS
    try:
        dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        pass

    # Formato epoch milliseconds
    try:
        ms = int(ts_str)
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass

    # Formato epoch seconds
    try:
        s = float(ts_str)
        dt = datetime.fromtimestamp(s, tz=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass

    # Se nada funcionar, retornar como está
    return ts_str


def normalizar_ip(ip_str: str) -> str:
    """Normalizar endereço IP para formato padrão."""
    if not ip_str:
        return "0.0.0.0"

    ip_str = ip_str.strip()

    # Já está no formato correto
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_str):
        octetos = ip_str.split(".")
        # Validar que cada octeto é 0-255
        try:
            octetos = [str(int(o)) for o in octetos]
            return ".".join(octetos)
        except ValueError:
            pass

    # Formato hexadecimal ou outro - retornar como está
    return ip_str


def normalizar_user_agent(ua_str: str) -> str:
    """Normalizar string de user-agent."""
    if not ua_str:
        return "unknown"

    ua_str = ua_str.strip()

    # Remover caracteres de controle
    ua_clean = re.sub(r'[\x00-\x1f\x7f]', '', ua_str)

    # Limitar tamanho
    if len(ua_clean) > 500:
        ua_clean = ua_clean[:500] + "..."

    return ua_clean


def normalizar_evento(evento: dict) -> dict:
    """Normalizar um evento de log completo."""
    resultado = {}

    # Campos obrigatórios normalizados
    resultado["timestamp"] = normalizar_timestamp(
        evento.get("timestamp", evento.get("@timestamp", ""))
    )
    resultado["origem_ip"] = normalizar_ip(
        evento.get("source_ip", evento.get("src_ip", evento.get("ip", "")))
    )
    resultado["destino_ip"] = normalizar_ip(
        evento.get("dest_ip", evento.get("dst_ip", evento.get("destino", "")))
    )
    resultado["user_agent"] = normalizar_user_agent(
        evento.get("user_agent", evento.get("ua", evento.get("user-agent", "")))
    )

    # Preservar outros campos
    for key, value in evento.items():
        if key not in ["timestamp", "source_ip", "src_ip", "ip", "dest_ip", "dst_ip",
                       "user_agent", "ua", "user-agent"]:
            resultado[key] = value

    return resultado
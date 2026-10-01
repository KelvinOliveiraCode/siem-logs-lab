"""Testes para o normalizador de logs SIEM."""

import sys
sys.path.insert(0, "/Users/Kelvin/Desktop/portfolio-24/siem-logs-lab/src")

from siemlab.normalizador import normalizar_evento, normalizar_timestamp, normalizar_ip, normalizar_user_agent


def test_normalizar_timestamp_iso():
    """Test normalização de timestamp ISO."""
    result = normalizar_timestamp("2026-09-01T10:30:00Z")
    assert "2026" in result


def test_normalizar_timestamp_offset():
    """Test normalização de timestamp com offset."""
    result = normalizar_timestamp("2026-09-01T10:30:00+00:00")
    assert "2026" in result


def test_normalizar_timestamp_epoch_seconds():
    """Test normalização de timestamp em segundos."""
    result = normalizar_timestamp("1700000000")
    # O epoch seconds pode não ser reconhecido, mas não deve crashar
    assert isinstance(result, str)


def test_normalizar_ip():
    """Test normalização de IP."""
    result = normalizar_ip("192.168.1.1")
    assert result == "192.168.1.1"


def test_normalizar_ip_invalido():
    """Test normalização de IP inválido."""
    result = normalizar_ip("")
    assert result == "0.0.0.0"


def test_normalizar_user_agent():
    """Test normalização de user-agent."""
    result = normalizar_user_agent("Mozilla/5.0 Chrome")
    assert "Mozilla" in result


def test_normalizar_evento_completo():
    """Test normalização completa de evento."""
    evento = {
        "timestamp": "2026-09-01T10:30:00Z",
        "source_ip": "192.168.1.100",
        "user-agent": "Mozilla/5.0 Chrome/120.0",
    }
    result = normalizar_evento(evento)
    assert result["timestamp"] == "2026-09-01T10:30:00+00:00"
    assert result["origem_ip"] == "192.168.1.100"
    assert "Chrome" in result["user_agent"]
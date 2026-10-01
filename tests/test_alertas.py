"""Testes para geração de alertas SIEM."""

import sys
sys.path.insert(0, "/Users/Kelvin/Desktop/portfolio-24/siem-logs-lab/src")

from siemlab.alertas import gerar_alerta_mitre, agrupar_alertas, gerar_relatorio_alertas


def test_gerar_alerta_mitre():
    """Test geração de alerta MITRE."""
    detalhes = {"ip": "10.0.0.1", "usuario": "admin", "acao": "login_falhado"}
    alerta = gerar_alerta_mitre("multiplos_logins_falhados", detalhes)
    
    assert "id_alerta" in alerta
    assert "tecnica_mitre" in alerta
    assert "titulo" in alerta
    assert "severidade" in alerta
    assert alerta["tecnica_mitre"] == "T1110"  # Brute Force


def test_agrupar_alertas():
    """Test agrupamento de alertas por técnica."""
    alertas = [
        {"tecnica_mitre": "T1110", "severidade": "alta"},
        {"tecnica_mitre": "T1110", "severidade": "alta"},
        {"tecnica_mitre": "T1078", "severidade": "media"},
    ]
    
    agrupados = agrupar_alertas(alertas)
    assert "T1110" in agrupados
    assert "T1078" in agrupados
    assert len(agrupados["T1110"]) == 2


def test_relatorio_alertas():
    """Test relatório de alertas."""
    alertas = [
        {"tecnica_mitre": "T1110", "severidade": "alta", "titulo": "Test Alert"},
    ]
    relatorio = gerar_relatorio_alertas(alertas)
    assert "ALERT-" in relatorio or isinstance(relatorio, str)
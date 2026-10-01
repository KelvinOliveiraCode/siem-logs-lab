"""Testes da CLI, do normalizador e do relatorio.

CLI, normaliser and report tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siemlab.alertas import agrupar_alertas, gerar_alerta_mitre, gerar_relatorio_alertas
from siemlab.cli import _tipo_da_regra, construir_parser, main
from siemlab.normalizador import (
    normalizar_evento,
    normalizar_ip,
    normalizar_timestamp,
    normalizar_user_agent,
)
from siemlab.relatorio import gerar_relatorio_json, gerar_relatorio_resumo

RAIZ = Path(__file__).resolve().parents[1]
LOGS = RAIZ / "dados" / "logs-sinteticos.jsonl"
REGRAS = RAIZ / "dados" / "regras-sigma.yaml"


class TestNormalizadorTimestamp:
    """Normalizacao de tempo."""

    def test_iso_com_z(self) -> None:
        assert normalizar_timestamp("2026-09-01T10:30:00Z")

    def test_iso_com_offset(self) -> None:
        assert normalizar_timestamp("2026-09-01T10:30:00+00:00")

    def test_iso_sem_timezone(self) -> None:
        assert normalizar_timestamp("2026-09-01T10:30:00")

    def test_vazio_cai_para_agora(self) -> None:
        # O normalizador substitui campo ausente por "agora", para manter o
        # schema estavel. Ver README, Limitacoes: isso significa que evento
        # sem timestamp passa a ancorar a janela de correlacao no presente.
        assert normalizar_timestamp("")

    def test_invalido_passa_atraves(self) -> None:
        # Nao valida: devolve o que recebeu. A validacao real e feita por
        # quem consome, nao aqui.
        assert normalizar_timestamp("nao-e-data") == "nao-e-data"


class TestNormalizadorIP:
    """Normalizacao de endereco."""

    def test_ipv4_valido(self) -> None:
        assert normalizar_ip("10.0.0.1") == "10.0.0.1"

    def test_ipv4_invalido_passa_atraves(self) -> None:
        # Nao valida a faixa; normaliza o formato. Um IP de inventario
        # invalido precisa aparecer no alerta, nao virar 0.0.0.0 as broncas.
        assert normalizar_ip("999.999.999.999") == "999.999.999.999"

    def test_vazio_cai_para_zero(self) -> None:
        assert normalizar_ip("") == "0.0.0.0"

    def test_none_cai_para_zero(self) -> None:
        assert normalizar_ip(None) == "0.0.0.0"


class TestNormalizadorUserAgent:
    """Normalizacao de user-agent."""

    def test_curl(self) -> None:
        assert "curl" in normalizar_user_agent("curl/8.0.1").lower()

    def test_vazio_cai_para_unknown(self) -> None:
        assert normalizar_user_agent("") == "unknown"


class TestNormalizadorEvento:
    """Normalizacao do evento inteiro."""

    def test_campos_presentes_sao_preservados(self) -> None:
        e = normalizar_evento({
            "timestamp": "2026-09-01T10:30:00Z",
            "origem_ip": "10.0.0.1",
            "tipo_evento": "login_falhido",
            "usuario": "ana",
        })
        assert e["origem_ip"] == "10.0.0.1"
        assert e["tipo_evento"] == "login_falhido"

    def test_campos_ausentes_cao_preenchidos(self) -> None:
        e = normalizar_evento({})
        assert e["origem_ip"] == "0.0.0.0"
        assert e["user_agent"] == "unknown"
        assert e["timestamp"]

    def test_ip_invalido_e_preservado(self) -> None:
        e = normalizar_evento({"origem_ip": "nao-e-ip"})
        assert e["origem_ip"] == "nao-e-ip"

    def test_nao_quebra_com_none(self) -> None:
        assert isinstance(normalizar_evento({"origem_ip": None}), dict)


class TestAlertas:
    """Geracao e agrupamento de alertas."""

    def test_alerta_tem_tecnica(self) -> None:
        a = gerar_alerta_mitre("multiplos_logins_falhados", {"ip": "10.0.0.1"})
        assert a["tecnica_mitre"].startswith("T")

    def test_tipo_desconhecido_cai_em_padrao(self) -> None:
        a = gerar_alerta_mitre("tipo_inexistente", {})
        assert a["tecnica_mitre"].startswith("T")

    def test_severidade_varia_por_tipo(self) -> None:
        alta = gerar_alerta_mitre("multiplos_logins_falhados", {})
        media = gerar_alerta_mitre("enumeracao_recursos", {})
        assert alta["severidade"] == "alta"
        assert media["severidade"] == "media"

    def test_agrupa_por_tecnica(self) -> None:
        alertas = [
            {"tecnica_mitre": "T1110"},
            {"tecnica_mitre": "T1110"},
            {"tecnica_mitre": "T1078"},
        ]
        g = agrupar_alertas(alertas)
        assert len(g["T1110"]) == 2
        assert len(g["T1078"]) == 1

    def test_agrupa_sem_tecnica(self) -> None:
        assert "Desconhecido" in agrupar_alertas([{}])

    def test_relatorio_alertas_e_json(self) -> None:
        texto = gerar_relatorio_alertas([{"id_alerta": "x"}])
        assert json.loads(texto)["total_alertas"] == 1


class TestRelatorio:
    """Formatacao do relatorio."""

    def test_json_tem_metadado(self) -> None:
        dados = json.loads(gerar_relatorio_json([{"id": "a"}], 10))
        assert dados["metadado"]["eventos_processados"] == 10
        assert dados["metadado"]["total_alertas"] == 1

    def test_json_com_lista_vazia(self) -> None:
        dados = json.loads(gerar_relatorio_json([], 0))
        assert dados["metadado"]["total_alertas"] == 0

    def test_resumo_conta_severidade(self) -> None:
        alertas = [
            {"severidade": "alta", "tecnica_mitre": "T1110"},
            {"severidade": "alta", "tecnica_mitre": "T1110"},
            {"severidade": "media", "tecnica_mitre": "T1078"},
        ]
        resumo = json.loads(gerar_relatorio_resumo(alertas))
        assert resumo["por_severidade"]["alta"] == 2
        assert resumo["por_technique"]["T1110"] == 2

    def test_resumo_vazio(self) -> None:
        resumo = json.loads(gerar_relatorio_resumo([]))
        assert resumo["total_alertas"] == 0


class TestMapeamentoTipo:
    """Fallback de titulo para tipo de alerta."""

    def test_apos_falhas_ganha_de_falha(self) -> None:
        # A ordem importa: "falha" contido em "apos falhas" invertia o
        # alerta de login bem-sucedido em alerta de forca bruta.
        assert _tipo_da_regra("Login bem-sucedido apos falhas") == (
            "login_sucesso_apos_falhas"
        )

    def test_falha_simples(self) -> None:
        assert _tipo_da_regra("Multiplas falhas de login") == (
            "multiplos_logins_falhados"
        )

    def test_bloqueado(self) -> None:
        assert _tipo_da_regra("Conexao para destino bloqueado") == (
            "conexao_saida_bloqueio"
        )

    def test_desconhecido_usa_padrao(self) -> None:
        assert _tipo_da_regra("regra sem palavra chave") == (
            "multiplos_logins_falhados"
        )


class TestCLI:
    """Interface de linha de comando."""

    def test_processar_retorna_zero(self, capsys) -> None:
        codigo = main(["processar", str(LOGS), "--regras", str(REGRAS)])
        assert codigo == 0
        assert "Eventos processados" in capsys.readouterr().out

    def test_processar_mostra_tecnicas(self, capsys) -> None:
        main(["processar", str(LOGS), "--regras", str(REGRAS)])
        saida = capsys.readouterr().out
        assert "T1110" in saida

    def test_processar_grava_saida(self, capsys, tmp_path) -> None:
        destino = tmp_path / "a.json"
        codigo = main([
            "processar", str(LOGS), "--regras", str(REGRAS), "--saida", str(destino)
        ])
        assert codigo == 0
        assert destino.exists()

    def test_resumir_retorna_zero(self, capsys) -> None:
        assert main(["resumir", str(LOGS), "--regras", str(REGRAS)]) == 0
        assert "total_alertas" in capsys.readouterr().out

    def test_log_inexistente_retorna_dois(self, capsys) -> None:
        codigo = main(["processar", "nao-existe.jsonl", "--regras", str(REGRAS)])
        assert codigo == 2
        assert "Erro" in capsys.readouterr().err

    def test_regras_inexistente_retorna_dois(self, capsys) -> None:
        codigo = main(["processar", str(LOGS), "--regras", "nao-existe.yaml"])
        assert codigo == 2

    def test_sem_subcomando_falha(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code != 0

    def test_help_principal(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0

    def test_help_processar(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["processar", "--help"])
        assert exc.value.code == 0

    def test_regras_obrigatorio(self) -> None:
        with pytest.raises(SystemExit):
            main(["processar", str(LOGS)])

    def test_parser_aceita_argumentos(self) -> None:
        parser = construir_parser()
        args = parser.parse_args(["processar", "x.jsonl", "--regras", "y.yaml"])
        assert args.logs == "x.jsonl"
        assert args.regras == "y.yaml"
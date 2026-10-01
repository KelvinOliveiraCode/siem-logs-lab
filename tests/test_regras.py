"""Testes do motor de regras e do parse Sigma."""

from __future__ import annotations

from pathlib import Path

import pytest

from siemlab.regras import RegraSigma, avaliar_regra, carregar_regra_yaml

DADOS = Path(__file__).resolve().parents[1] / "dados"
REGRAS = DADOS / "regras-sigma.yaml"


class TestRegraSigmaAvaliacao:
    """Casamento de evento contra selecao."""

    def test_string_literal_faz_match(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": "login_falhado"})
        assert r.avaliar({"tipo_evento": "login_falhado"}) is True

    def test_string_literal_divergente_nao_faz_match(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": "login_falhado"})
        assert r.avaliar({"tipo_evento": "sucesso"}) is False

    def test_campo_ausente_nao_faz_match(self) -> None:
        r = RegraSigma("n", "d", {"usuario": "admin"})
        assert r.avaliar({"tipo_evento": "x"}) is False

    def test_valor_em_lista_faz_match(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": ["a", "b"]})
        assert r.avaliar({"tipo_evento": "b"}) is True

    def test_valor_fora_da_lista_nao_faz_match(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": ["a", "b"]})
        assert r.avaliar({"tipo_evento": "c"}) is False

    def test_operador_contains(self) -> None:
        r = RegraSigma("n", "d", {"url": {"contains": "admin"}})
        assert r.avaliar({"url": "/admin/login"}) is True

    def test_operador_contains_negativo(self) -> None:
        r = RegraSigma("n", "d", {"url": {"contains": "admin"}})
        assert r.avaliar({"url": "/publico"}) is False

    def test_operador_gt(self) -> None:
        r = RegraSigma("n", "d", {"bytes": {"gt": 1000}})
        assert r.avaliar({"bytes": 5000}) is True

    def test_operador_gt_negativo(self) -> None:
        r = RegraSigma("n", "d", {"bytes": {"gt": 1000}})
        assert r.avaliar({"bytes": 10}) is False

    def test_operador_lt(self) -> None:
        r = RegraSigma("n", "d", {"porta": {"lt": 1024}})
        assert r.avaliar({"porta": 80}) is True

    def test_operador_regex(self) -> None:
        r = RegraSigma("n", "d", {"user_agent": {"regex": "^curl"}})
        assert r.avaliar({"user_agent": "curl/8.0"}) is True

    def test_operador_regex_negativo(self) -> None:
        r = RegraSigma("n", "d", {"user_agent": {"regex": "^curl"}})
        assert r.avaliar({"user_agent": "Mozilla/5.0"}) is False

    def test_operador_eq_com_tipos_diferentes(self) -> None:
        r = RegraSigma("n", "d", {"porta": {"eq": 443}})
        assert r.avaliar({"porta": "443"}) is True

    def test_operador_exists_presente(self) -> None:
        r = RegraSigma("n", "d", {"usuario": {"exists": True}})
        assert r.avaliar({"usuario": "ana"}) is True

    def test_selecao_vazia_faz_match(self) -> None:
        assert RegraSigma("n", "d", {}).avaliar({"qualquer": 1}) is True

    def test_duas_condicoes_ambas_precisam_valer(self) -> None:
        r = RegraSigma("n", "d", {"a": "1", "b": "2"})
        assert r.avaliar({"a": "1", "b": "3"}) is False


class TestRegraSigmaFiltro:
    """O filtro descarta o que a selecao pegou."""

    def test_filtro_que_nao_casa_descarta(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": "login_falhado"}, filtro={"origem_ip": "10.0.0.1"})
        assert r.avaliar({"tipo_evento": "login_falhado", "origem_ip": "8.8.8.8"}) is False

    def test_filtro_que_casa_mantem(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": "login_falhado"}, filtro={"origem_ip": "10.0.0.1"})
        assert r.avaliar({"tipo_evento": "login_falhado", "origem_ip": "10.0.0.1"}) is True

    def test_selecao_que_nao_casa_ignora_filtro(self) -> None:
        r = RegraSigma("n", "d", {"tipo_evento": "sucesso"}, filtro={"origem_ip": "10.0.0.1"})
        assert r.avaliar({"tipo_evento": "login_falhado", "origem_ip": "10.0.0.1"}) is False


class TestCarregarYaml:
    """Leitura do arquivo de regras."""

    def test_carrega_regras_do_repo(self) -> None:
        regras = carregar_regra_yaml(REGRAS)
        assert regras is not None

    def test_arquivo_de_regras_tem_chave_rules(self) -> None:
        import yaml

        dados = yaml.safe_load(REGRAS.read_text(encoding="utf-8"))
        assert isinstance(dados["rules"], list)
        assert len(dados["rules"]) == 7

    def test_regras_tem_os_campos_sigma(self) -> None:
        import yaml

        for r in yaml.safe_load(REGRAS.read_text(encoding="utf-8"))["rules"]:
            assert "title" in r
            assert "detection" in r
            assert "selection" in r["detection"]

    def test_regras_tem_tecnica_mitre(self) -> None:
        import yaml

        for r in yaml.safe_load(REGRAS.read_text(encoding="utf-8"))["rules"]:
            assert r["tecnica_mitre"].startswith("T")

    def test_todas_as_regras_avaliam_sem_erro(self) -> None:
        from siemlab.regras import carregar_regras

        evento = {
            "tipo_evento": "login_falhido",
            "usuario": "admin",
            "origem_ip": "10.0.0.1",
            "timestamp": "2026-09-01T10:30:00Z",
        }
        for regra in carregar_regras(REGRAS):
            assert isinstance(regra.avaliar(evento), bool)

    def test_carregar_regras_devolve_sete(self) -> None:
        from siemlab.regras import carregar_regras

        assert len(carregar_regras(REGRAS)) == 7

    def test_arquivo_inexistente_levanta_oserror(self) -> None:
        with pytest.raises(OSError):
            carregar_regra_yaml(DADOS / "nao-existe.yaml")


class TestAvaliarRegra:
    """A funcao que devolve o dict de resultado."""

    def test_nao_e_coletada_pelo_pytest(self) -> None:
        # O nome precisa comecar com avaliar_, nunca com test, senao o pytest
        # trata a funcao como caso de teste.
        assert avaliar_regra.__name__.startswith("avaliar")

    def test_devolve_disparou_verdadeiro(self) -> None:
        r = RegraSigma("regra-x", "desc", {"tipo_evento": "login_falhado"})
        assert avaliar_regra(r, {"tipo_evento": "login_falhado"})["disparou"] is True

    def test_devolve_disparou_falso(self) -> None:
        r = RegraSigma("regra-x", "desc", {"tipo_evento": "login_falhado"})
        assert avaliar_regra(r, {"tipo_evento": "outro"})["disparou"] is False

    def test_devolve_id_da_regra(self) -> None:
        r = RegraSigma("regra-x", "desc", {})
        assert avaliar_regra(r, {})["id_regra"] == "regra-x"
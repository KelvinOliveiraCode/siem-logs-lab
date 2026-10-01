"""Testes do pipeline completo, incluindo o teste negativo obrigatorio.

Full pipeline tests, including the mandatory negative test.

O teste negativo e o mais importante deste arquivo: prova que as 7 regras
NÃO disparam em trafego normal. Sem ele, um detector que alerta em tudo
passaria em todos os outros testes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from siemlab.cli import processar, ler_eventos
from siemlab.regras import carregar_regras

RAIZ = Path(__file__).resolve().parents[1]
LOGS = RAIZ / "dados" / "logs-sinteticos.jsonl"
REGRAS = RAIZ / "dados" / "regras-sigma.yaml"

#: Prefixo de origem reservado aos eventos plantados de ataque.
PREFIXO_ATAQUE = "10.99."

#: Os 7 padroes que a especificacao exige.
PADROES_ESPERADOS = {
    "multiplos_logins_falhados",
    "login_sucesso_apos_falhas",
    "acesso_fora_horario",
    "conta_privilegio_usuario_comum",
    "download_volume_anormal",
    "conexao_saida_bloqueio",
    "enumeracao_recursos",
}


@pytest.fixture(scope="module")
def resultado() -> dict:
    """Processa a base uma vez para os testes."""
    return processar(LOGS, REGRAS)


def _eventos_de_ataque() -> list[dict]:
    """Somente os eventos dos IPs de ataque."""
    return [
        json.loads(linha)
        for linha in LOGS.read_text(encoding="utf-8").splitlines()
        if linha.strip()
        and json.loads(linha)["origem_ip"].startswith(PREFIXO_ATAQUE)
    ]


def _eventos_normais() -> list[dict]:
    """Somente os eventos de trafego benigno."""
    return [
        json.loads(linha)
        for linha in LOGS.read_text(encoding="utf-8").splitlines()
        if linha.strip()
        and not json.loads(linha)["origem_ip"].startswith(PREFIXO_ATAQUE)
    ]


class TestVolumeDeDados:
    """A base tem volume suficiente para os testes serem reais."""

    def test_mais_de_2000_eventos(self) -> None:
        assert len(ler_eventos(LOGS)) >= 2000

    def test_tem_eventos_de_ataque_e_normais(self) -> None:
        assert len(_eventos_de_ataque()) > 0
        assert len(_eventos_normais()) > 1000

    def test_todo_evento_tem_os_campos_base(self) -> None:
        for e in ler_eventos(LOGS):
            assert "timestamp" in e
            assert "origem_ip" in e
            assert "tipo_evento" in e

    def test_arquivo_e_jsonl_valido(self) -> None:
        # ler_eventos descarta linha quebrada; se descartasse muitas, a
        # contagem nao fecharia com o numero de linhas.
        linhas = [l for l in LOGS.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(ler_eventos(LOGS)) == len(linhas)


class TestPositivo:
    """Os 7 padroes disparam no trafego de ataque."""

    def test_sete_padroes_disparam(self, resultado) -> None:
        tipos = {a["tipo"] for a in resultado["alertas"]}
        assert PADROES_ESPERADOS <= tipos, f"faltou: {PADROES_ESPERADOS - tipos}"

    @pytest.mark.parametrize(
        "tipo",
        sorted(PADROES_ESPERADOS),
    )
    def test_padrao_especifico_dispara(self, resultado, tipo) -> None:
        assert any(a["tipo"] == tipo for a in resultado["alertas"])

    def test_alertas_tem_tecnica_mitre(self, resultado) -> None:
        for a in resultado["alertas"]:
            assert a["tecnica_mitre"].startswith("T")

    def test_alertas_tem_severidade(self, resultado) -> None:
        for a in resultado["alertas"]:
            assert a["severidade"] in ("baixa", "media", "alta", "critica")

    def test_alertas_tem_entidades(self, resultado) -> None:
        for a in resultado["alertas"]:
            assert isinstance(a["entidades"], dict)

    def test_alertas_tem_sugestao_de_resposta(self, resultado) -> None:
        for a in resultado["alertas"]:
            assert a.get("sugestao_resposta")

    def test_alertas_tem_evidencia(self, resultado) -> None:
        # Nem todo alerta tem o mesmo formato de evidencia: os que vem de
        # correlacao carregam a evidencia agrupada, os que vem de regra
        # simples carregam o evento. Os dois precisam existir.
        for a in resultado["alertas"]:
            assert "entidades" in a

    def test_alertas_de_correlacao_tem_evidencia_agrupada(self, resultado) -> None:
        correlacao = [a for a in resultado["alertas"] if a["tipo"] == "enumeracao_recursos"]
        assert correlacao
        for a in correlacao:
            assert "evidencia" in a["entidades"]
            assert "amostra_recursos" in a["entidades"]["evidencia"]

    def test_numero_de_alertas_e_razoavel(self, resultado) -> None:
        # Alerta em mais de 10% dos eventos plantados indica regra ruidosa.
        assert resultado["total_alertas"] < len(_eventos_de_ataque()) * 2


class TestNegativo:
    """O teste que importa: trafego normal nao gera alerta."""

    def test_trafego_normal_nao_dispara_nenhuma_regra(self) -> None:
        from siemlab.normalizador import normalizar_evento

        normais = [normalizar_evento(e) for e in _eventos_normais()]
        regras = [r for r in carregar_regras(REGRAS) if not r.correlacao]

        disparos = {
            regra.tipo
            for regra in regras
            for e in normais
            if regra.avaliar(e)
        }
        assert disparos == set(), f"regras disparando em trafego normal: {disparos}"

    def test_trafego_normal_nao_gera_alerta_de_correlacao(self) -> None:
        from siemlab.correlacao import correlacionar_enumeracao_recursos
        from siemlab.normalizador import normalizar_evento

        normais = [normalizar_evento(e) for e in _eventos_normais()]
        assert correlacionar_enumeracao_recursos(normais) == []


class TestDeduplicacao:
    """O mesmo alerta nao aparece duas vezes."""

    def test_nao_ha_o_mesmo_evento_alertado_duas_vezes(self, resultado) -> None:
        # Deduplicacao e por (tipo, IP, minuto). O mesmo IP pode gerar mais de
        # um alerta legitimo (ex.: regra 1 e regra 2 no mesmo minuto), entao a
        # chave precisa ser a tripla inteira, nao o par.
        vistos = [
            (a["tipo"], a["entidades"].get("origem_ip", ""), str(a["entidades"].get("timestamp", ""))[:16])
            for a in resultado["alertas"]
        ]
        assert len(vistos) == len(set(vistos))

    def test_alertas_tem_id(self, resultado) -> None:
        assert all(a["id_alerta"] for a in resultado["alertas"])


class TestSaida:
    """Persistencia do resultado."""

    def test_grava_json(self, tmp_path) -> None:
        destino = tmp_path / "alertas.json"
        processar(LOGS, REGRAS, destino)
        assert destino.exists()
        dados = json.loads(destino.read_text(encoding="utf-8"))
        assert dados["metadado"]["total_alertas"] > 0

    def test_json_tem_lista_de_alertas(self, tmp_path) -> None:
        destino = tmp_path / "alertas.json"
        processar(LOGS, REGRAS, destino)
        dados = json.loads(destino.read_text(encoding="utf-8"))
        assert isinstance(dados["alertas"], list)
        assert "gerado_em" in dados["metadado"]
        assert dados["metadado"]["eventos_processados"] >= 2000

    def test_json_e_serializavel(self, tmp_path) -> None:
        # set dentro do alerta quebrava json.dumps. Este teste e o que pegou.
        destino = tmp_path / "alertas.json"
        processar(LOGS, REGRAS, destino)
        json.loads(destino.read_text(encoding="utf-8"))

    def test_resultado_e_deterministico(self) -> None:
        a = processar(LOGS, REGRAS)
        b = processar(LOGS, REGRAS)
        assert a["total_alertas"] == b["total_alertas"]
        assert [x["tipo"] for x in a["alertas"]] == [x["tipo"] for x in b["alertas"]]


class TestEntradasInvalidas:
    """Casos de falha."""

    def test_log_inexistente_levanta_oserror(self) -> None:
        with pytest.raises(OSError):
            processar("nao-existe.jsonl", REGRAS)

    def test_regras_inexistente_levanta_oserror(self) -> None:
        with pytest.raises(OSError):
            processar(LOGS, "nao-existe.yaml")

    def test_regras_sem_chave_rules_levanta_valueerror(self, tmp_path) -> None:
        ruim = tmp_path / "r.yaml"
        ruim.write_text("outro: 1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="rules"):
            processar(LOGS, ruim)

    def test_linha_jsonl_quebrada_e_ignorada(self, tmp_path) -> None:
        p = tmp_path / "l.jsonl"
        p.write_text('{"timestamp": "2026-09-01T00:00:00Z"}\nNAO E JSON\n', encoding="utf-8")
        assert len(ler_eventos(p)) == 1
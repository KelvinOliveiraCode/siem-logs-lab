"""Motor de detecção de regras SIEM - parseia condições Sigma e aplica sobre eventos."""

import re
from pathlib import Path

import yaml


class RegraSigma:
    """Representa uma regra de detecção no formato Sigma."""

    def __init__(self, nome, descricao, selecao, filtro=None, condition="and",
                 tipo="", tecnica_mitre="", severidade="media", correlacao=False):
        self.nome = nome
        self.descricao = descricao
        self.selecao = selecao  # dicionário de condições
        self.filtro = filtro  # filtro opcional
        self.condition = condition  # "and" ou "or"
        self.tipo = tipo
        self.tecnica_mitre = tecnica_mitre
        self.severidade = severidade
        self.correlacao = correlacao

    def avaliar(self, evento: dict) -> bool:
        """Avaliar se a regra corresponde ao evento."""
        # Aplica seleção (conditions no Sigma)
        if self.selecao:
            match = self._match_selecao(evento, self.selecao)
            if not match:
                return False

        # Aplica filtro opcional
        if self.filtro:
            match = self._match_selecao(evento, self.filtro)
            if not match:
                return False

        return True

    def _match_selecao(self, evento: dict, selecao: dict) -> bool:
        """Verificar se todas as condições da seleção são atendidas."""
        for campo, valor in selecao.items():
            valor_evento = evento.get(campo)
            if valor_evento is None:
                return False

            # Verificar se o valor corresponde
            if isinstance(valor, str):
                # String literal - correspondência exata
                if str(valor_evento) != valor:
                    return False
            elif isinstance(valor, list):
                # Lista - verificar se o valor está na lista
                if valor_evento not in valor:
                    return False
            elif isinstance(valor, dict):
                # Dicionário de padrões (regex, etc.)
                for op, val in valor.items():
                    if op == "contains":
                        if val not in str(valor_evento):
                            return False
                    elif op == "regex":
                        if not re.search(val, str(valor_evento)):
                            return False
                    elif op == "gt":
                        if not (float(valor_evento) > float(val)):
                            return False
                    elif op == "lt":
                        if not (float(valor_evento) < float(val)):
                            return False
                    elif op == "eq":
                        if str(valor_evento) != str(val):
                            return False
                    elif op == "exists":
                        if valor_evento is None:
                            return False
            else:
                # Tipo desconhecido - correspondência simples
                if str(valor_evento) != str(valor):
                    return False

        return True


def carregar_regras(caminho: str | Path) -> list[RegraSigma]:
    """Carregar todas as regras de um arquivo YAML.

    Load every rule from a YAML file.

    O arquivo tem a forma ``rules:`` seguido de uma lista. A convencao Sigma
    oficial separa regras com ``---`` (multi-documento), mas `yaml.safe_load`
    so devolve o primeiro documento - o parser falhava com
    ``ComposerError: found another document``. Por isso o arquivo deste
    repositorio usa lista unica.

    Args:
        caminho: Caminho do ``.yaml``.

    Returns:
        Lista de :class:`RegraSigma`, na ordem do arquivo.

    Raises:
        ValueError: Se o arquivo nao tiver a chave ``rules`` em lista.
    """
    with open(caminho, "r", encoding="utf-8") as f:
        dados = yaml.safe_load(f)

    if isinstance(dados, list):
        itens = dados
    elif isinstance(dados, dict):
        itens = dados.get("rules")
    else:
        itens = None

    if not isinstance(itens, list):
        raise ValueError(
            "Esperado uma lista de regras, ou um mapa com a chave 'rules' "
            "/ expected a list of rules, or a map with the 'rules' key"
        )

    regras: list[RegraSigma] = []
    for item in itens:
        deteccao = item.get("detection") or {}
        regras.append(
            RegraSigma(
                nome=item.get("title", item.get("id", "sem-nome")),
                descricao=item.get("description", item.get("descricao", "")),
                selecao=deteccao.get("selection", {}) or {},
                filtro=deteccao.get("filter"),
                condition=deteccao.get("condition", "and") or "and",
                tipo=item.get("tipo", "") or "",
                tecnica_mitre=item.get("tecnica_mitre", "") or "",
                severidade=item.get("severity", "media") or "media",
                correlacao=bool(item.get("correlacao", False)),
            )
        )
    return regras


def carregar_regra_yaml(caminho: str | Path) -> RegraSigma:
    """Carregar a primeira regra de um arquivo YAML.

    Load the first rule of a YAML file.

    Mantido por compatibilidade: quem chamava `carregar_regra_yaml` continua
    funcionando, mas a lista inteira sai de :func:`carregar_regras`.

    Args:
        caminho: Caminho do ``.yaml``.

    Returns:
        A primeira :class:`RegraSigma` do arquivo.
    """
    regras = carregar_regras(caminho)
    if not regras:
        raise ValueError(f"{caminho}: nenhuma regra encontrada / no rule found")
    return regras[0]


def avaliar_regra(regra: RegraSigma, evento: dict) -> dict:
    """Avaliar uma regra contra um evento e devolver o resultado.

    Evaluate a rule against an event and return the result.

    O nome **nao** comeca com `test` de proposito: uma funcao chamada
    `testar_regra` no modulo e coletada pelo pytest como um caso de teste e
    falha em setup complaining de fixture `regra` inexistente. O bug apareceu
    no primeiro `pytest` deste repositorio.

    The name deliberately does not start with `test`: a function named
    `testar_regra` in the module gets collected by pytest as a test case and
    fails in setup looking for a missing `regra` fixture.
    """
    disparou = regra.avaliar(evento)

    return {
        "id_regra": regra.nome,
        "nome": regra.nome,
        "descricao": regra.descricao,
        "disparou": disparou,
        "condition": regra.condition,
    }
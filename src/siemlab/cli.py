"""CLI do siem-logs-lab.

Interface de linha de comando para processar logs com regras de deteccao.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from siemlab.alertas import gerar_alerta_mitre
from siemlab.correlacao import (
    correlacionar_acesso_horario_insolito,
    correlacionar_enumeracao_recursos,
    correlacionar_logins_falhados,
)
from siemlab.normalizador import normalizar_evento
from siemlab.regras import avaliar_regra, carregar_regras
from siemlab.relatorio import gerar_relatorio_json, gerar_relatorio_resumo

#: Resposta sugerida por tipo de alerta.
RESPOSTA_SUGERIDA = {
    "multiplos_logins_falhados": "Bloquear o IP de origem e revogar a sessao ativa.",
    "login_sucesso_apos_falhas": "Trocar a senha da conta e verificar o que foi acessado.",
    "acesso_fora_horario": "Confirmar com o titular se o acesso era esperado.",
    "conta_privilegio_usuario_comum": "Auditar a conta de privilegio e revogar credencial.",
    "download_volume_anormal": "Verificar exfiltracao e notificar o responsavel pelo dado.",
    "conexao_saida_bloqueio": "Bloquear o destino e identificar o processo que iniciou.",
    "enumeracao_recursos": "Verificar se houve reconhecimento de rede interno.",
}


def ler_eventos(caminho: str | Path) -> list[dict]:
    """Le eventos de um arquivo JSONL, pulando linha invalida.

    Read events from a JSONL file, skipping invalid lines.

    Args:
        caminho: Caminho do ``.jsonl``.

    Returns:
        Lista de eventos crus, ainda sem normalizar.
    """
    eventos: list[dict] = []
    with open(caminho, "r", encoding="utf-8") as fh:
        for linha in fh:
            linha = linha.strip()
            if not linha:
                continue
            try:
                eventos.append(json.loads(linha))
            except json.JSONDecodeError:
                # Linha quebrada nao derruba o lote inteiro: um log real tem
                # linha truncada, e perder 2400 eventos por causa de uma e
                # pior do que reportar a linha e seguir.
                continue
    return eventos


def _regra_por_nome(regras: list, titulo: str):
    """Acha uma regra pelo titulo, de forma tolerante.

    Find a rule by title, tolerantly.
    """
    alvo = titulo.lower()
    for r in regras:
        if alvo in r.nome.lower():
            return r
    return None


def processar(
    caminho_logs: str | Path,
    caminho_regras: str | Path,
    saida: str | Path | None = None,
) -> dict:
    """Processa logs e devolve o relatorio completo.

    Process logs and return the full report.

    Args:
        caminho_logs: Arquivo JSONL de eventos.
        caminho_regras: Arquivo YAML de regras.
        saida: Caminho opcional para gravar o JSON.

    Returns:
        Dicionario com ``total_eventos``, ``total_alertas`` e ``alertas``.
    """
    regras = carregar_regras(caminho_regras)
    eventos = [normalizar_evento(e) for e in ler_eventos(caminho_logs)]

    alertas: list[dict] = []

    # Regra a regra: assim cada alerta carrega a tecnica MITRE correta.
    # Regra marcada `correlacao: true` e padrao, nao propriedade de evento:
    # ela nao e aplicada aqui, e sim pela correlacao correspondente.
    for regra in regras:
        if regra.correlacao:
            continue
        for evento in eventos:
            resultado = avaliar_regra(regra, evento)
            if not resultado["disparou"]:
                continue
            tipo = regra.tipo or _tipo_da_regra(regra.nome)
            alerta = gerar_alerta_mitre(tipo, evento)
            alerta["tecnica_mitre"] = regra.tecnica_mitre or alerta["tecnica_mitre"]
            alerta["severidade"] = regra.severidade or alerta["severidade"]
            alertas.append(alerta)

    # Correlacoes com janela temporal, que so a correlacao faz.
    correlacoes = correlacionar_logins_falhados(eventos)
    for c in correlacoes:
        alertas.append(
            gerar_alerta_mitre(c["tipo"], c)
        )

    fora_horario = correlacionar_acesso_horario_insolito(eventos)
    for c in fora_horario:
        alertas.append(gerar_alerta_mitre(c["tipo"], c))

    enumeracao = correlacionar_enumeracao_recursos(eventos)
    for c in enumeracao:
        alertas.append(gerar_alerta_mitre(c["tipo"], c))

    # Deduplica: mesma regra + mesma origem + mesmo minuto.
    vistos: set[tuple] = set()
    unicos: list[dict] = []
    for a in alertas:
        chave = (
            a.get("tipo"),
            str(a.get("entidades", {}).get("ip", "")),
            str(a.get("entidades", {}).get("timestamp", ""))[:16],
        )
        if chave in vistos:
            continue
        vistos.add(chave)
        unicos.append(a)

    for a in unicos:
        a["sugestao_resposta"] = RESPOSTA_SUGERIDA.get(a.get("tipo", ""), "")

    if saida:
        destino = Path(saida)
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(
            gerar_relatorio_json(unicos, len(eventos)), encoding="utf-8"
        )

    return {
        "total_eventos": len(eventos),
        "total_alertas": len(unicos),
        "alertas": unicos,
    }


def _tipo_da_regra(titulo: str) -> str:
    """Fallback: mapeia titulo para tipo de alerta.

    Fallback: map a title to an alert type.

    Usado so quando a regra nao declara `tipo` no YAML. A ordem dos testes
    importa: "apos falhas" precisa ser testado antes de "falha", senao a
    regra de login bem-sucedido vira alerta de forca bruta.
    """
    t = titulo.lower()
    if "apos falha" in t or "after" in t:
        return "login_sucesso_apos_falhas"
    if "horario" in t:
        return "acesso_fora_horario"
    if "privilegio" in t or "privilege" in t:
        return "conta_privilegio_usuario_comum"
    if "download" in t:
        return "download_volume_anormal"
    if "bloque" in t:
        return "conexao_saida_bloqueio"
    if "enumeracao" in t or "discovery" in t:
        return "enumeracao_recursos"
    if "falha" in t or "failed" in t:
        return "multiplos_logins_falhados"
    return "multiplos_logins_falhados"


def _cmd_processar(args: argparse.Namespace) -> int:
    """Subcomando processar.

    The process subcommand.
    """
    resultado = processar(args.logs, args.regras, args.saida)

    print(f"Eventos processados: {resultado['total_eventos']}")
    print(f"Alertas gerados: {resultado['total_alertas']}")
    print()

    if resultado["alertas"]:
        print("Alertas por tecnica MITRE:")
        contagem: dict[str, int] = {}
        for a in resultado["alertas"]:
            t = a.get("tecnica_mitre", "desconhecida")
            contagem[t] = contagem.get(t, 0) + 1
        for t in sorted(contagem):
            print(f"  {t}: {contagem[t]}")
    else:
        print("Nenhum alerta disparado.")

    if args.saida:
        print(f"\nRelatorio gravado em: {args.saida}")

    return 0


def _cmd_resumir(args: argparse.Namespace) -> int:
    """Subcomando resumir, que mostra o alerta por tipo.

    The summarise subcommand, which shows alerts by type.
    """
    resultado = processar(args.logs, args.regras, None)
    print(gerar_relatorio_resumo(resultado["alertas"]))
    return 0


def construir_parser() -> argparse.ArgumentParser:
    """Monta o parser de argumentos.

    Build the argument parser.
    """
    parser = argparse.ArgumentParser(
        prog="siemlab",
        description=(
            "Processa logs com regras de deteccao e gera alertas MITRE ATT&CK. "
            "Processes logs with detection rules and emits MITRE ATT&CK alerts."
        ),
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    p_proc = sub.add_parser("processar", help="Processa logs e grava alertas em JSON.")
    p_proc.add_argument("logs", help="Arquivo JSONL de eventos.")
    p_proc.add_argument("--regras", required=True, help="Arquivo YAML de regras.")
    p_proc.add_argument("--saida", help="Grava o relatorio JSON neste caminho.")
    p_proc.set_defaults(func=_cmd_processar)

    p_res = sub.add_parser("resumir", help="Mostra os alertas agrupados por tipo.")
    p_res.add_argument("logs", help="Arquivo JSONL de eventos.")
    p_res.add_argument("--regras", required=True, help="Arquivo YAML de regras.")
    p_res.set_defaults(func=_cmd_resumir)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada da CLI.

    CLI entry point.
    """
    parser = construir_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"Erro / error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
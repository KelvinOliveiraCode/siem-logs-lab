"""Confere encoding dos arquivos de texto versionados.

Check the encoding of every tracked text file.

Um BOM UTF-8 no inicio de arquivo, um caractere de substituicao (U+FFFD) ou
um ideograma CJK indicam que alguma passagem de texto corrompeu a escrita. No
GitHub o resultado aparece como lixo no diff, entao e mais barato falhar aqui.

Um BOM e a marca EF BB BF que nao deve aparecer em arquivo deste
repositorio. Um U+FFFD e um caractere de substituicao. Um ideograma CJK e um
texto em japones, chines ou coreano. Nenhum dos tres pertence a este
repositorio.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Raiz do repositorio.
RAIZ = Path(__file__).resolve().parent.parent

#: Extensoes de texto varridas.
EXTENSOES = {
    ".py", ".md", ".txt", ".json", ".yml", ".yaml",
    ".toml", ".cfg", ".ini", ".ps1",
}

#: Extensoes binarias ignoradas de proposito.
BINARIOS = {".png", ".jpg", ".mp4", ".woff", ".woff2"}

#: Diretorios e arquivos ignorados.
IGNORADOS = {".git", ".pytest_cache", "__pycache__", ".coverage"}

#: Marcacao UTF-8 no inicio do arquivo.
BOM = b"\xef\xbb\xbf"

#: Intervalo de ideogramas CJK.
CJK = range(0x3000, 0x9FFF + 1)

#: Caractere de substituicao.
SUBSTITUICAO = 0xFFFD


def varrer(raiz: Path = RAIZ) -> tuple[list[tuple[str, int, str]], int]:
    """Procura arquivo de texto com encoding invalido.

    Find text files holding an invalid encoding marker.

    Args:
        raiz: Diretorio a varrer.

    Returns:
        Tupla ``(problemas, conferidos)``; cada problema e
        ``(caminho, linha, motivo)`` e ``conferidos`` conta os arquivos
        varridos.
    """
    problemas: list[tuple[str, int, str]] = []
    conferidos = 0
    for caminho in sorted(raiz.rglob("*")):
        if not caminho.is_file():
            continue
        if any(parte in IGNORADOS for parte in caminho.parts):
            continue
        extensao = caminho.suffix.lower()
        if extensao in BINARIOS:
            continue
        if extensao not in EXTENSOES:
            continue
        relativo = str(caminho.relative_to(raiz))
        bruto = caminho.read_bytes()
        conferidos += 1
        if bruto.startswith(BOM):
            problemas.append((relativo, 0, "BOM UTF-8 no inicio"))
            continue
        try:
            texto = bruto.decode("utf-8")
        except UnicodeDecodeError as exc:
            problemas.append((
                relativo, 0, f"nao decodifica como UTF-8: {exc}",
            ))
            continue
        for numero, linha in enumerate(texto.splitlines(), 1):
            for caractere in linha:
                ponto = ord(caractere)
                if ponto == SUBSTITUICAO:
                    problemas.append((
                        relativo, numero,
                        "caractere de substituicao U+FFFD",
                    ))
                    break
                if ponto in CJK:
                    problemas.append((
                        relativo, numero,
                        f"ideograma CJK U+{ponto:04X}",
                    ))
                    break
    return problemas, conferidos


def main() -> int:
    """Executa a varredura e reporta.

    Run the sweep and report.
    """
    problemas, conferidos = varrer()
    if not problemas:
        print(
            f"encoding ok: {conferidos} arquivo(s) conferidos, "
            "nenhum BOM, U+FFFD ou ideograma CJK"
        )
        return 0
    print(
        f"encoding FALHOU: {len(problemas)} ocorrencia(s) "
        f"em {conferidos} arquivo(s) conferidos"
    )
    for caminho, linha, motivo in problemas:
        onde = f"{caminho}:{linha}" if linha else caminho
        print(f"  {onde}: {motivo}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

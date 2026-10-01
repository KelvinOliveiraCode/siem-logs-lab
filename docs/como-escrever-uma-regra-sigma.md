# Como escrever uma regra Sigma

Este repositorio implementa um **subconjunto** do formato Sigma. O que funciona
aqui, o que nao funciona, e o que escrever quando a regra nao cabe no modelo.

## O que Sigma e

Sigma e um padrao aberto de regras de deteccao. A ideia e que a regra seja
legivel por humano e portavel entre SIEMs: voce escreve uma vez e roda em
varios produtos.

E o oposto do que a maioria dos SIEMproprietarios usa, onde regra e SQL
embutido e cada produto tem a sua sintaxe.

## A anatomia de uma regra

```yaml
- title: Download de volume anormal
  id: SIEM-0005
  tipo: download_volume_anormal
  level: high
  descricao: Transferencia muito acima do perfil normal da conta.
  tecnica_mitre: T1005
  severity: alta
  detection:
    condition: and
    selection:
      tipo_evento: download
      bytes: {gt: 100000000}
```

| Campo | Opcional | Para que serve |
|---|---|---|
| `title` | nao | Nome legivel |
| `id` | nao | Identificador estavel |
| `tipo` | **simples** | Identificador do alerta gerado |
| `detection.selection` | nao | Condicoes que precisam valer |
| `detection.filter` | sim | Condicoes que **descartam** o alerta |
| `detection.condition` | sim | `and` ou `or` entre blocos |
| `level` | sim | Severidade nativa Sigma |
| `technica_mitre` | **simples** | Tecnica ATT&CK |

Os campos `tipo` e `technica_mitre` **nao** existem no Sigma oficial. Sao
extensoes deste repositorio, e existem por um motivo concreto: antes deles o
tipo era deduzido do `title` por substring, e isso errou. "Login bem-sucedido
apos falhas" casava com "falha" e saia como alerta de forca bruta. Inferir
tipo de nome de texto e fragil; campo explicito nao erra.

## Operadores suportados

| Operador | Exemplo | Significado |
|---|---|---|
| literal | `tipo_evento: login_falhido` | Igualdade exata |
| lista | `tipo_evento: [a, b]` | Um dos valores |
| `contains` | `{contains: admin}` | Substring |
| `regex` | `{regex: "^curl"}` | Expressao regular |
| `gt` | `{bytes: {gt: 1000}}` | Maior que |
| `lt` | `{porta: {lt: 1024}}` | Menor que |
| `eq` | `{porta: {eq: 443}}` | Igualdade, convertendo tipo |
| `exists` | `{usuario: {exists: true}}` | Campo presente |

Varios operadores podem combinar no mesmo campo:

```yaml
selection:
  bytes: {gt: 1000000, lt: 500000000}
```

## O que **nao** funciona aqui

| Recurso Sigma | Por que nao |
|---|---|
| `selection_*` (variantes nomeadas) | Nao implementado |
| `aggregation` | Precisa de janela temporal; nao cabe em regra de evento |
| `timeframe` | Idem - e temporal |
| `condition: 1 of selection_*` | Depende de variantes nomeadas |
| Modificadores de campo (`\|re`, `\|base64`) | Nao implementados |
| YAML multi-documento | Ver abaixo |

### Multi-documento

O Sigma oficial separa regras com `---`, uma por documento YAML. `yaml.safe_load`
so devolve o primeiro e falha com `ComposerError: found another document`.

Por isso este repositorio usa **lista unica** sob a chave `rules`:

```yaml
rules:
  - title: ...
  - title: ...
```

O `carregar_regras` aceita os dois formatos, mas o gerador deste repositorio
sempre escreve lista unica.

## Como escrever uma regra que de fato detecta

### 1. Comece pelo ruido, nao pelo ataque

Escreva primeiro a regra de trafego normal e veja quantos alertas ela gera. Se
gerar mais que dois em uma hora de trafego real, a regra esta larga demais.

Concretamente neste repositorio: a regra 7 casava `acesso_recurso` e gerava
**562 alertas** em trafego normal. So virou deteccao util depois de virar
correlacao por recurso distinto.

### 2. Verifique o campo no log

Campo que a regra exige e que o log nao tem produz regra que nunca dispara.
Foi o caso de `conta_privilegiada` e `destino_bloqueado`: as regras existiam, o
gerador de log nao produzia esses campos, e o detector ficava em silencio.

Confirme com o log real, nao com a documentacao do formato que voce quer usar:

```powershell
Get-Content dados/logs-sinteticos.jsonl -TotalCount 1
```

### 3. Escreva o teste negativo

Um alerta que dispara em trafego limpo nao e deteccao. O teste negativo deste
repositorio:

```python
def test_trafego_normal_nao_dispara_nenhuma_regra(self):
    normais = [normalizar_evento(e) for e in _eventos_normais()]
    disparos = {
        regra.tipo
        for regra in regras
        for e in normais
        if regra.avaliar(e)
    }
    assert disparos == set()
```

Sem esse teste, qualquer regra passa nos outros testes - inclusive a regra que
alerta em tudo.

### 4. Decida: evento ou correlacao?

Regra de evento quando **um evento** basta para afirmar. Regra de correlacao
quando o que caracteriza o ataque e o **conjunto**.

Enumeracao: um acesso a recurso e normal. Quarenta e cinco recursos distintos
em 90 s nao e.

Forca bruta: uma falha de login e normal. Seis falhas do mesmo IP em 60 s nao
e.

### 5. Marque a tecnica ATT&CK

`tecnica_mitre` e o que liga o alerta ao framework que o analista usa para
decidir a resposta. Sem ele, o alerta e "algo aconteceu"; com ele, e "isto e
T1110, que significa forca bruta de credencial".

## Checklist antes de commitar uma regra

- [ ] Teste positivo: dispara no evento sintetico correspondente
- [ ] Teste negativo: **nao** dispara em trafego normal
- [ ] Todos os campos exigidos existem no log
- [ ] `tipo` e `tecnica_mitre` preenchidos
- [ ] Filtro aplicado quando ha condicao que exclui falso positivo
- [ ] `severity` coerente com a resposta sugerida
- [ ] Numero de alertas em trafego normal proximo de zero
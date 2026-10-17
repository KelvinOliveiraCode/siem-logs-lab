<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">

# siem-logs-lab

Pipeline local de deteccao que le logs JSONL, aplica 7 regras no formato Sigma, correlaciona eventos em janela temporal e emite alertas mapeados ao MITRE ATT&CK. Tudo roda localmente, sem SIEM pago e sem enviar logs para fora da maquina.

## Problema / Por que existe

Um alerta que so diz "algo aconteceu" nao faz triagem. O analista precisa da tecnica, das entidades envolvidas, da linha do tempo e de uma sugestao de resposta. A maioria dos exemplos de SIEM mostra apenas o alerta que dispara e omite o que nao dispara: um detector que alarme em trafego normal e ruido com boa formatacao. Este e um laboratorio local de logica de SIEM e trabalho de SOC, com teste negativo incluso: as 7 regras sao validadas contra a massa de trafego benigno da base fornecida e nao devem produzir alerta neles.

## O que faz

- Le um arquivo JSONL de eventos, ignorando linhas quebradas sem derrubar o lote restante.
- Normaliza timestamp, IP e user-agent; preserva os demais campos do evento.
- Aplica 7 regras de deteccao no formato Sigma (subconjunto) evento a evento.
- Executa 3 correlacoes com janela temporal deslizante ancorada no evento mais recente visto, não no relogio do sistema: multiplas falhas de login do mesmo IP, acesso fora do horario habitual e enumeracao de recursos distintos por IP.
- Emite alertas com tecnica MITRE ATT&CK, severidade, entidades e sugestao de resposta por tipo.
- Deduplica por (tipo, IP, minuto) e pode gravar o relatorio em JSON.
- Inclui o comando `resumir`, que agrupa alertas por tipo.

## Stack

- Python 3.10+
- PyYAML, para leitura das regras YAML
- pytest e pytest-cov, dependencias de desenvolvimento para os testes
- Nenhuma dependencia externa de SIEM, banco de dados ou servico de nuvem

## Como funciona

O pipeline executa estes passos:

```
evento -> normalizar -> regra Sigma evento a evento  -> alerta
                              \-> correlacao temporal --^
```

1. `ler_eventos` le o JSONL linha a linha e ignora linha invalida.
2. `normalizar_evento` padroniza timestamp e IP. Campos ausentes recebem valores defaults (`0.0.0.0`, `unknown`, "agora") para manter o schema estavel.
3. `carregar_regras` parseia o YAML com as 7 regras sob a chave `rules` (lista unica, pois `yaml.safe_load` nao le documentos Sigma separados por `---`).
4. Cada regra nao-marcada como `correlacao` e avaliada contra cada evento. Regras marcadas, como `enumeracao_recursos`, sao tratadas pela correlacao, pois nenhum evento isolado prova enumeracao.
5. `correlacao.py` agrupa eventos por IP e aplica a janela temporal deslizante.
6. `alertas.py` monta o dicionario do alerta com tecnica MITRE ATT&CK, severidade e sugestao de resposta por tipo.
7. `relatorio.py` serializa o relatorio JSON; `cli.py` deduplica e imprime o resumo por tecnica.

Regras em `dados/regras-sigma.yaml`:

1. Multiplas falhas de login do mesmo IP — T1110, alta
2. Login bem-sucedido apos falhas — T1078, alta
3. Acesso fora do horario habitual — T1078, media
4. Conta de privilegio em uso por usuario comum — T1078, alta
5. Download de volume anormal — T1005, alta
6. Conexao de saida para destino bloqueado — T1071, alta
7. Enumeracao de recursos — T1087, media, tratada por correlacao

## Como rodar

```powershell
# 1. Criar ambiente e instalar dependencias
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .

# 2. Executar os testes
python -m pytest tests/ -v

# 3. Processar a base fornecida
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
```

Outros comandos:

```powershell
python -m siemlab resumir dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml --saida saida/alertas.json
python gerar_logs.py dados/logs-sinteticos.jsonl   # regenera a base com semente fixa
```

Exemplo de saida com a base incluida no repositorio:

```
Eventos processados: 2378
Alertas gerados: 26

Alertas por tecnica MITRE:
  T1005: 3
  T1071: 2
  T1078: 17
  T1087: 1
  T1110: 3
```

Estrutura de um alerta:

```json
{
  "id_alerta": "ALERT-20261001123202",
  "tecnica_mitre": "T1110",
  "titulo": "[T1110] Multiplos Logins Falhados",
  "severidade": "alta",
  "tipo": "multiplos_logins_falhados",
  "entidades": {
    "timestamp": "2026-09-01T00:00:15+00:00",
    "origem_ip": "10.99.0.1",
    "tipo_evento": "login_falhido",
    "usuario": "admin"
  },
  "sugestao_resposta": "Bloquear o IP de origem e revogar a sessao ativa."
}
```

Os numeros acima sao saida real da base incluida, reproduzivel executando o comando com os arquivos do repositorio. Nao sao uma promessa de deteccao em ambiente de produção.

## Estrutura do projeto

```
siem-logs-lab/
  src/siemlab/
    cli.py          interface de linha de comando (processar, resumir)
    correlacao.py   janela temporal deslizante e agrupamento por IP
    normalizador.py timestamp, IP, user-agent, normalizacao de evento
    regras.py       motor Sigma (selection, filter, operadores)
    alertas.py      alertas MITRE ATT&CK
    relatorio.py    saida JSON e resumo
    __main__.py     permite executar como python -m siemlab
  gerar_logs.py     gerador da base com semente fixa
  dados/
    logs-sinteticos.jsonl  2.378 eventos, 7 padroes plantados
    regras-sigma.yaml      7 regras
    mitre-attack.yaml      subconjunto de tecnicas
  docs/
    regras-de-deteccao.md
    como-escrever-uma-regra-sigma.md
  exemplos/         saida real
  tests/            testes do pipeline, incluindo teste negativo
```

## Trade-offs e decisoes

- Janela ancorada no evento mais recente, não no relogio. Um SIEM processa historico. Com `datetime.now()`, um log de ontem seria descartado inteiro antes da correlacao e a regra nunca dispararia. Este foi o primeiro bug da implementacao; o sintoma era "nenhuma correlacao nunca dispara".
- Tipo do alerta por campo `tipo` explicito no YAML, não inferido do titulo. Inferir por substring rotulou "Login bem-sucedido apos falhas" como forca bruta, gerando alertas com o rotulo errado.
- Enumeracao conta recursos distintos por IP, não eventos. Contar eventos transformava trafego web normal em varredura e produzia centenas de falsos positivos em trafego normal.
- Evidencia de enumeracao e lista ordenada, não `set`. `set` quebra `json.dumps` e impedia a gravacao do relatorio.
- `testar_regra` renomeado para `avaliar_regra`. Funcoes começando com `test` sao coletadas pelo pytest e falham ao procurar uma fixture inexistente.
- Regras que exigem campos ausentes do log ficam silenciosas sem erro. `conta_privilegiada` e `destino_bloqueado` estavam nas regras e nao no gerador; detector quieto é o pior tipo de bug.
- Linha JSONL quebrada e ignorada, não aborta o lote. Um log real tem linha truncada; perder milhares de eventos por uma linha e pior que reportar a linha e seguir.
- Subconjunto do Sigma, não Sigma completo. Sem `selection_*` nomeado, `aggregation`, `timeframe` nem modificadores de campo. Padroes que exigem agregacao temporal cabem na secao de correlacao, não na regra de evento.

## Limitações conhecidas

- Janela temporal não trata fuso horario. Assume UTC; evento com offset diferente entra na janela deslocado.
- Normalizador preenche campo ausente com `0.0.0.0`, `unknown` e "agora". Evento sem timestamp ancora a janela no presente; eventos sem IP se agrupam sob `0.0.0.0`. Em log real, esses casos precisam de tratamento antes.
- Sem validacao de faixa de IP. `999.999.999.999` passa. Um IP invalido aparece no alerta, mas a deteccao nao sinaliza.
- Severidade vem da regra, não e calculada. Um SIEM real combina alertas: duas `media` do mesmo IP viram um `alta`. Aqui não.
- Sem correlacao entre hosts. Comprometimento distribuido (escada entre varias maquinas) exige estado compartilhado que o pipeline local nao tem.
- Correlacao de forca bruta e por IP, e IP pode ser compartilhado. Em rede com NAT, varios usuarios legítimos errando a senha viram um alerta só.
- Testado com a base sintética incluida. Comportamento em log de produção nao e garantido por este repositorio.

## Licença

MIT. Ver [LICENSE](LICENSE).

## Autor

Kelvin Oliveira — https://github.com/KelvinOliveiraCode · https://kelvinoliveiracode.github.io/portfolio/

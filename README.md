<div align="center">

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/tests-115%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-87%25-brightgreen?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square" alt="Windows">
</p>

# siem-logs-lab

**Pipeline local de deteccao: 7 regras, correlacao temporal e alertas MITRE ATT&CK sobre 2.378 eventos sinteticos.**

</div>

---

## PT-BR

### O que e

CLI que le um log em JSONL, normaliza os eventos, aplica 7 regras de deteccao
no formato Sigma, correlaciona eventos em janela temporal deslizante e emite
alertas mapeados no MITRE ATT&CK. Tudo local, sem SIEM pago e sem enviar
log para lugar nenhum.

### Por que foi feito

Logica de SIEM e trabalho de SOC. Um alerta que so diz "algo aconteceu" nao faz
triagem - o analista precisa da tecnica, das entidades envolvidas, da linha do
tempo e de uma sugestao de resposta.

E a parte que quase ninguem demonstra: a regra que **nao** dispara. Um detector
que alerta em trafego normal e ruido com formatacao boa. Aqui a base tem 2.305
eventos de trafego benigno e as 7 regras produzem **zero** alerta neles - isso
esta em teste, nao em promessa.

### Como rodar

```powershell
# 1. Instalar
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Validar
python -m pytest tests/ -v

# 3. Executar
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
```

Saida real:

```
Eventos processados: 2378
Alertas gerados: 26

Alertas por tecnica MITRE:
  T1005: 3
  T1071: 2
  T1078: 17
  T1087: 1
  T1110: 3

Relatorio gravado em: exemplos/alertas.json
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

Outros comandos:

```powershell
python -m siemlab resumir dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml --saida saida/alertas.json
python gerar_logs.py dados/logs-sinteticos.jsonl    # regenera a base com semente fixa
```

### O que aprendi

- **Enumeracao e padrao, nao propriedade de evento.** A regra 7 era
  `tipo_evento: acesso_recurso`, aplicada evento a evento, e gerava **562
  alertas em trafego normal** - todo acesso a recurso disparava. Nenhum evento
  isolado prova enumeracao; o que prova e variacao de alvo. Virou correlacao por
  recurso **distinto** por IP, e o mesmo trafego passou a dar zero. A segunda
  parte do bug: a correlacao contava *eventos*, nao recursos distintos, entao
  trafego web normal com 20 requisicoes parecia varredura.
- **A janela temporal nao pode usar o relogio.** `remover_velhos` usava
  `datetime.now()`, entao um arquivo de log de ontem era inteiro descartado
  antes da correlacao e a regra 1 nunca disparava. Um SIEM processa historico.
  A janela e ancorada no evento mais recente. Era o primeiro bug da
  implementacao, e o sintoma era "nenhuma correlacao nunca dispara".
- **Inferir tipo pelo titulo do texto falha.** "Login bem-sucedido apos falhas"
  casava com a checagem de "falha" e saia como alerta de forca bruta - 586
  alertas com o rotulo errado. Resolvi com campo `tipo` explicito no YAML. Texto
  livre serve para humano, nao para dispatch de codigo.
- **`set` dentro do alerta quebra a serializacao.** A evidencia de enumeracao
  guardava `set(recursos[:20])`, e `json.dumps` levantou `TypeError: Object of
  type set is not JSON serializable` - no caminho feliz, com log valido. Agora e
  lista ordenada, que e deterministica e serializa.
- **Funcao que comeca com `test` vira caso de teste.** `testar_regra` no modulo
  de producao foi coletada pelo pytest e falhou em setup procurando fixture
  `regra`. Virou `avaliar_regra`. Bug bobo que custou uma rodada de diagnostico.
- **Campo que a regra exige precisa existir no log.** `conta_privilegiada` e
  `destino_bloqueado` estavam nas regras e nao no gerador de log: as regras
  ficavam em silencio sem erro nenhum. Detector quieto e o pior tipo de bug.

### Limitacoes

- **Subconjunto do Sigma, nao Sigma completo.** Nao implementa `selection_*`
  nomeado, `aggregation`, `timeframe` nem modificadores de campo. Padrao que
  precisa de agregacao temporal nao cabe em regra de evento - e o que a secao de
  correlacao cobre.
- **A janela temporal nao trata fuso horario.** Assume UTC. Evento com offset
  diferente entra na janela deslocado.
- **Normalizador preenche campo ausente com `0.0.0.0`, `unknown` e "agora".**
  Serve para manter o schema estavel, mas evento sem timestamp passa a ancorar
  a janela no presente, e eventos sem IP se agrupam todos sob `0.0.0.0`. Num
  log real, esses casos precisam de tratamento antes.
- **Nao valida faixa de IP.** `999.999.999.999` passa. Um IP de inventario
  invalido precisa aparecer no alerta, mas a deteccao nao signaliza.
- **Severidade vem da regra, nao e calculada.** SIEM real combina alertas: dois
  `media` do mesmo IP viram um `alta`. Aqui nao.
- **Nao correlaciona entre hosts.** Deteccao distribuida (comprometimento
  ladderando em varias maquinas) exige estado compartilhado que este pipeline
  local nao tem.
- **Correlacao de forca bruta e por IP, e IP pode ser compartilhado.** Em rede
  com NAT, seis usuarios legitimos errando a senha viram um alerta so.

### Licenca

MIT. Ver [LICENSE](LICENSE).

---

## EN

### What it is

A CLI that reads a JSONL log, normalises the events, applies 7 detection rules
in Sigma format, correlates events in a sliding time window, and emits alerts
mapped to MITRE ATT&CK. Entirely local, no paid SIEM, and no log data leaving
the machine.

### Why it was built

SIEM logic is SOC work. An alert that only says "something happened" does not
triage - the analyst needs the technique, the entities involved, the timeline
and a suggested response.

And there is the part almost nobody demonstrates: the rule that **does not**
fire. A detector that alerts on normal traffic is noise with good formatting.
Here the base has 2,305 benign events and the 7 rules produce **zero** alerts on
them - and that is in a test, not in a promise.

### How to run

```powershell
# 1. Install
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Validate
python -m pytest tests/ -v

# 3. Run
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
```

Real output:

```
Eventos processados: 2378
Alertas gerados: 26

Alertas por tecnica MITRE:
  T1005: 3
  T1071: 2
  T1078: 17
  T1087: 1
  T1110: 3

Relatorio gravado em: exemplos/alertas.json
```

Alert structure:

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

Other commands:

```powershell
python -m siemlab resumir dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml
python -m siemlab processar dados/logs-sinteticos.jsonl --regras dados/regras-sigma.yaml --saida saida/alertas.json
python gerar_logs.py dados/logs-sinteticos.jsonl    # regenerate the base with a fixed seed
```

### What I learned

- **Enumeration is a pattern, not an event property.** Rule 7 was
  `tipo_evento: acesso_recurso`, applied per event, and produced **562 alerts on
  normal traffic** - every resource access fired. No single event proves
  enumeration; what proves it is target variation. It became a correlation over
  **distinct** resources per IP, and the same traffic now yields zero. The second
  half of the bug: the correlation counted *events*, not distinct resources, so
  ordinary web traffic with 20 requests looked like a scan.
- **The time window must not use the wall clock.** `remover_velhos` used
  `datetime.now()`, so yesterday's whole log file was evicted before correlation
  and rule 1 never fired. A SIEM processes history. The window is anchored to the
  newest event. That was the first bug in the implementation, and the symptom was
  "no correlation ever fires".
- **Inferring the type from the title fails.** "Login bem-sucedido apos falhas"
  matched the "falha" check and came out as a brute-force alert - 586 alerts with
  the wrong label. I fixed it with an explicit `tipo` field in the YAML. Free text
  is fine for humans, not for dispatching code.
- **A `set` inside an alert breaks serialisation.** The enumeration evidence
  stored `set(recursos[:20])`, and `json.dumps` raised `TypeError: Object of type
  set is not JSON serializable` - on the happy path, with a valid log. It is now
  a sorted list, which is deterministic and serialises.
- **A function starting with `test` becomes a test case.** `testar_regra` in the
  production module got collected by pytest and failed in setup looking for a
  `regra` fixture. It is now `avaliar_regra`. A silly bug that cost a diagnostic
  round.
- **A field a rule needs must exist in the log.** `conta_privilegiada` and
  `destino_bloqueado` were in the rules but not in the log generator: the rules
  sat silent with no error at all. A quiet detector is the worst kind of bug.

### Limitations

- **Sigma subset, not full Sigma.** No named `selection_*`, no `aggregation`, no
  `timeframe`, no field modifiers. A pattern that needs temporal aggregation does
  not fit in an event rule - which is what the correlation section covers.
- **The time window does not handle time zones.** It assumes UTC. An event with a
  different offset enters the window shifted.
- **The normaliser fills missing fields with `0.0.0.0`, `unknown` and "now".**
  That keeps the schema stable, but an event with no timestamp ends up anchoring
  the window to the present, and events with no IP all group under `0.0.0.0`. In
  a real log those cases need handling first.
- **No IP range validation.** `999.999.999.999` passes. An invalid inventory IP
  needs to show up in the alert, but detection does not flag it.
- **Severity comes from the rule, it is not computed.** A real SIEM combines
  alerts: two `media` from one IP become one `alta`. This one does not.
- **No cross-host correlation.** Distributed detection (compromise laddering
  across machines) needs shared state this local pipeline does not have.
- **Brute-force correlation is per IP, and IPs can be shared.** On a NATed
  network, six legitimate users mistyping their password become one alert.

### License

MIT. See [LICENSE](LICENSE).

---

## Estrutura / Structure

```
src/siemlab/
  normalizador.py  timestamp, IP, user-agent, evento
  regras.py        motor Sigma (selection, filter, operadores)
  correlacao.py    janela temporal deslizante e agrupamento
  alertas.py       alertas MITRE ATT&CK
  relatorio.py     saida JSON e resumo
  cli.py           interface de linha de comando
gerar_logs.py      gerador da base com semente fixa
dados/
  logs-sinteticos.jsonl  2.378 eventos, 7 padroes plantados
  regras-sigma.yaml      7 regras
  mitre-attack.yaml      subconjunto de tecnicas
docs/
  regras-de-deteccao.md
  como-escrever-uma-regra-sigma.md
exemplos/          saida real
tests/             115 testes
```

## Deteccao / Detection

```
evento -> normalizar -> regra por evento  --> alerta
                 \-> correlacao temporal --> alerta
```

## Licenca / License

MIT &mdash; [LICENSE](LICENSE)

---

<div align="center">
  <sub>Por <a href="https://github.com/KelvinOliveiraCode">Kelvin Oliveira</a> &middot;
  <a href="https://kelvinoliveiracode.github.io/portfolio/">portfolio</a></sub>
</div>
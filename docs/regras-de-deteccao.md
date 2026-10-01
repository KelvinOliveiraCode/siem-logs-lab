# Regras de deteccao

As 7 regras implementadas, o que cada uma detecta e por que esta escrita
assim.

## Panorama

| # | Regra | Tecnica MITRE | Severidade | Tipo de deteccao |
|---|---|---|---|---|
| 1 | Falhas de login do mesmo IP | T1110 Brute Force | alta | por evento + correlacao |
| 2 | Login bem-sucedido apos falhas | T1078 Valid Accounts | alta | por evento |
| 3 | Acesso fora do horario | T1078 | media | por evento + correlacao |
| 4 | Conta de privilegio por usuario comum | T1078 | alta | por evento |
| 5 | Download de volume anormal | T1005 Data Staged | alta | por evento |
| 6 | Conexao para destino bloqueado | T1071 | alta | por evento |
| 7 | Enumeracao de recursos | T1087 | media | **so por correlacao** |

## Por que a regra 7 nao e aplicada por evento

Este e o ponto mais importante do arquivo, e foi o maior bug da implementacao.

Enumeracao de recursos e um **padrao**, nao uma propriedade de evento. Nenhum
evento isolado prova enumeracao: acessar `/recurso_17` e perfeitamente normal.
O que caracteriza varredura e **variacao de alvo** - muitos recursos distintos
vindo da mesma origem em pouco tempo.

Na primeira versao, a regra 7 era `tipo_evento: acesso_recurso`, aplicada evento
a evento. Resultado: **562 alertas em trafego normal**. Todo acesso a recurso
disparava. Um detector que alerta em tudo nao detector: e ruido com formatacao
bonita.

A correcao tem duas partes:

1. A regra foi marcada `correlacao: true` no YAML e a CLI pula esse tipo de
   regra na aplicacao por evento.
2. `correlacionar_enumeracao_recursos` conta recursos **distintos** por IP, nao
   eventos. Antes contava eventos, e trafego normal de aplicacao web com 20
   requisicoes em um minuto parecia varredura.

Agora o mesmo trafego produz **zero** alerta, e os 45 recursos distintos do IP
de varredura produzem um.

## Regra 1 - falhas de login

Duas camadas:

- **Por evento:** qualquer `login_falhido` casa. Isso e pouco especifico de
  proposito - quem escreve log de autenticacao gera evento de falha por erro de
  digitacao o tempo todo.
- **Por correlacao:** `correlacionar_logins_falhados` conta falhas do mesmo IP
  em janela de 60 s. Tres ou mais e alerta.

A janela temporal e ancorada no **evento mais recente**, nao no relogio. Um
SIEM processa log historico: com `now()`, todo evento de ontem seria
descartado antes da correlacao e a regra nunca dispararia. Esse foi o primeiro
bug encontrado neste repositorio, e o sintoma era "nenhuma correlacao nunca
dispara".

## Regra 2 - login bem-sucedido apos falhas

Precisa dos dois: conta privilegiada **e** login bem-sucedido. So login
bem-sucedido e o que o usuario faz 200 vezes por dia. So conta privilegiada e
administrador operando normalmente.

O alerta dice se houve sucesso depois das falhas, porque essa e a diferenca
entre erro de digitacao e comprometimento de senha.

## Regra 3 - acesso fora do horario

Faixa 00h as 05h, quando nao ha atividade operacional. Cuidado com quem viaja
ou trabalha em turno - o alerta informa, nao bloqueia.

## Regra 4 - conta de privilegio por usuario comum

`conta_privilegiada: true` em sessao de quem nao e administrador. Em
ambiente pequeno o sinal e fraco porque quase ninguem tem conta privilegiada;
em ambiente com dominio AD e bem mais forte.

## Regra 5 - download de volume anormal

Limite de 100 MB por evento. O perfil de download legitimo depende da conta:
backup nightly passa disso tranquilo. Por isso o limiar e por evento e a
correlacao precisaria considerar o historico da conta para nao gerar ruido.

## Regra 6 - destino bloqueado

Sinal mais forte do conjunto: a organizacao **julgou** aquele destino
indesejado. A lista vem do inventario, nao esta neste repositorio - aqui so
trata o campo `destino_bloqueado` como booleano ja marcado.

## Regra 7 - enumeracao

Ver acima. 20 recursos distintos por IP dispara. Em rede com DHCP e NAT o IP
pode ser compartilhado, entao o alerta precisa de correlacao com outros
sinais antes de virar incidente.

## Deteccao por evento vs. por correlacao

| | Por evento | Por correlacao |
|---|---|---|
| Custo | O(N eventos x M regras) | O(N eventos) |
| Serve para | sinal forte e isolado | padrao que so existe no conjunto |
| Exemplo aqui | regra 6, destino bloqueado | regra 1, regra 7 |
| Risco | falso positivo se a regra for ampla | pode ignorar evento se o padrao nao fechar |

O erro de aplicacao e quase sempre o mesmo: transformar correlacao em regra de
evento. Foi o que aconteceu com a regra 7.

## Severidade

| Severidade | Significado | Resposta sugerida |
|---|---|---|
| `critica` | Confirmado, com impacto | Acao imediata |
| `alta` | Padrao forte de ataque | Investigar no mesmo dia |
| `media` | Comportamento atipico | Revisar na proxima janela |
| `baixa` | Informativo | Registrar |

A severidade vem da regra (`severity` no YAML), nao e calculada. Um SIEM real
calcula por combinacao - dois alertas `media` do mesmo IP viram um `alta`.
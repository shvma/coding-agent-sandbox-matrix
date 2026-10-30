# Вариант A: песочница Claude Code под managed settings

Базовая конфигурация стенда для варианта A, составленная по официальной документации. Это **не** политика, закрывающая найденное, — только включение песочницы так, чтобы её нельзя было обойти настройками репозитория. Политику разрешений под конкретные находки добавляют после первого прогона.

Отдельные прогоны SRT CLI лежат в [results](../results/2026-10-30/README.md). Они проверяют runtime, но не загрузку этого файла в Claude Code и не managed precedence. Интеграционный прогон Claude ещё не выполнен. Сетевой allowlist ниже пуст: перед пилотом его нужно согласовать с рабочими сервисами; это не готовый профиль повседневной разработки.

Установка: `./install-wizard.sh`. Это шаг человека: файл ложится в системный каталог и требует прав администратора.

## Что делает каждый ключ и откуда он взят

Ключи и их смысл сверены 2026-10-30 со страницами документации Claude Code (Markdown-версии страниц, загружены 2026-10-30):
- [Sandboxing](https://code.claude.com/docs/en/sandboxing) — S;
- [Settings reference](https://code.claude.com/docs/en/settings-reference) — R;
- [Managed settings](https://code.claude.com/docs/en/managed-settings) — M;
- [Permissions](https://code.claude.com/docs/en/permissions) — P.

`scripts/check.py` сверяет таблицу с `managed-settings.json`: у каждого ключа в колонке «Значение» должно стоять то же значение, что в файле, а у списков — каждый элемент.

| Ключ | Значение | Зачем | Источник |
|---|---|---|---|
| файл | `/Library/Application Support/ClaudeCode/managed-settings.json` | системный каталог managed settings на macOS | M |
| `allowManagedHooksOnly` | `true` | выполняются только хуки из managed settings. Хук из `.claude/settings.json` репозитория выполняется вне песочницы с полными правами пользователя | R: «only managed hooks run»; S: «command hooks, local MCP servers … status line command and `apiKeyHelper` run with your full access» |
| `allowManagedMcpServersOnly` | `true` | список разрешённых MCP-серверов берётся только из managed settings | R: «reads `allowedMcpServers` from managed settings alone» |
| `allowedMcpServers` | `[]` | пустой список: блокируются все MCP-серверы, которые добавляет пользователь или репозиторий (`.mcp.json`). Серверы для пилота вносятся сюда поимённо | R: «an empty array blocks every server users add» |
| `enableAllProjectMcpServers` | `false` | серверы из `.mcp.json` репозитория не одобряются без вопроса | R, `enableAllProjectMcpServers` |
| `sandbox.enabled` | `true` | включить песочницу для команд оболочки | S, «Enforce sandboxing with managed settings» |
| `sandbox.failIfUnavailable` | `true` | если песочница не стартует, Claude Code не запускается, а не работает без неё | S: «a missing dependency … blocks Claude Code from starting rather than falling back to unsandboxed execution» |
| `sandbox.allowUnsandboxedCommands` | `false` | выключить запасной выход: модель не может повторить упавшую команду вне песочницы. Песочница становится admin-required, и настройки репозитория, которые её ослабляют, игнорируются | S: «Claude Code ignores the `dangerouslyDisableSandbox` escape hatch»; про admin-required: «Requires Claude Code v2.1.285 or later» |
| `sandbox.autoAllowBashIfSandboxed` | `false` | команды в песочнице идут через обычные подтверждения. При `true` они выполняются без вопроса, в том числе запись в рабочий каталог файлов, которые потом исполнит кто-то вне песочницы (Makefile, `package.json`, `.envrc`; см. матрицу). Строгий старт для пилота; включение — решение по итогам замера числа подтверждений | R: «`true`: Claude Code runs sandboxed Bash commands without a permission prompt»; S: «Don't rely on any of the sandbox's restrictions … In auto-allow mode, that command can run without a permission prompt» |
| `sandbox.enableWeakerNetworkIsolation`, `sandbox.allowAppleEvents` | `false` | ключи, которые ослабляют песочницу и которые иначе можно включить из пользовательских настроек | S, «Keep developers from widening the policy» |
| `sandbox.filesystem.allowManagedReadPathsOnly` | `true` | учитываются только `allowRead` из managed settings: разработчик не может своим `allowRead` снова открыть закрытые пути | R: «only `allowRead` entries from managed settings are honored» |
| `sandbox.filesystem.denyRead` | `~/**/.env` | команды не читают `.env` ни в одном каталоге под домашним, в том числе в репозитории | S, пример: «`"denyRead": ["~/**/.env"]` … Every `.env` under the home directory stays blocked»; синтаксис путей — R, «Sandbox path prefixes» |
| `sandbox.network.allowedDomains` | `[]` | сеть для команд закрыта полностью; список доменов задаётся политикой развёртывания | S: allowed domains «start empty» |
| `sandbox.network.allowManagedDomainsOnly` | `true` | учитываются только домены из managed settings; остальные блокируются без вопроса | S, «Managed lockdown» |
| `sandbox.credentials.files` | `deny` для `~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.vault-token`, `~/.config/gh` | по умолчанию песочница **разрешает** их читать | S: «Reads: Most of the machine, including credential files such as `~/.ssh` and `~/.aws/credentials`»; «There is no built-in credential deny list» |
| `sandbox.credentials.envVars` | `deny` для `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | переменные удаляются из окружения команд. `ANTHROPIC_API_KEY` нужен самому Claude Code, но не его командам | S, «Protect credentials» |
| `permissions.deny` | `Read(~/.ssh/**)`, `Read(~/.aws/**)`, `Read(~/.azure/**)`, `Read(~/.config/gcloud/**)`, `Read(~/.kube/**)`, `Read(~/.docker/config.json)`, `Read(~/.netrc)`, `Read(~/.npmrc)`, `Read(~/.pypirc)`, `Read(~/.git-credentials)`, `Read(~/.vault-token)`, `Read(~/.config/gh/**)`, `Read(**/.env)`, `WebFetch`, `WebSearch` | песочница не закрывает встроенные инструменты Claude: «A `denyRead` entry doesn't stop the Read tool», «`allowedDomains` doesn't limit WebFetch». `WebFetch` и `WebSearch` запрещены целиком, как и сеть команд; для пилота разрешённые адреса добавляются правилами `WebFetch(domain:…)` | S; синтаксис `Read(**/.env)` и `WebFetch(domain:…)` — P |

Чего этот файл не закрывает. `apiKeyHelper` и `statusLine` из настроек репозитория: отдельного managed-ключа, который запрещал бы `apiKeyHelper`, в R нет; `statusLine` не из managed settings не запускается при `allowManagedHooksOnly` (R, `statusLine`: «When `allowManagedHooksOnly` is on … only the managed settings value runs»). Остаётся полагаться на защиту файлов `.claude` от записи командами (S, «Protected paths») и на просмотр репозитория до запуска. Это не проверено прогоном Claude Code.

## На чём держится граница

S, «OS-level enforcement»: «**macOS**: uses Seatbelt for sandbox enforcement», «**Linux**: uses bubblewrap for isolation», «**WSL2**: uses bubblewrap, same as Linux». Про Windows: «The sandbox doesn't run on native Windows».

## Что вне зоны действия (важно для матрицы)

Из раздела «Limitations» и «What runs outside the sandbox» (S):

- Песочница изолирует **команды оболочки** и их дочерние процессы. Встроенные инструменты (Read, Edit, Write, WebFetch, WebSearch) следуют правилам разрешений: `allowedDomains` не ограничивает WebFetch. Поэтому в матрице проекта у таких классов исход «вне зоны действия», а не «не держит».
- Команда, которую разработчик сам набрал через `!`, выполняется вне песочницы.
- Сеть фильтруется по имени хоста, TLS не вскрывается. Документация предупреждает, что широкие домены (например, `github.com`) дают путь для эксфильтрации и что возможен domain fronting.
- Локальный администратор может отредактировать сам managed-файл; от этого защищает переразвёртывание через MDM.
- Computer use работает на настоящем рабочем столе, а не в песочнице.

## Что не зафиксировано

- Версия Claude Code фиксируется при установке. Поведение admin-required песочницы, по S, «Requires Claude Code v2.1.285 or later». Мастер установки пишет `claude --version` в журнал; ниже v2.1.285 прогон не засчитывается.
- Список каталогов с ключами взят по типовым местам. Какие учётные данные реально лежат на машине разработчика, зависит от окружения; список дополняется в managed settings.

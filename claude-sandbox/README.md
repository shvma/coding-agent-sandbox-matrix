# Вариант A: песочница Claude Code под managed settings

Базовая конфигурация стенда для варианта A, составленная по официальной документации. Это **не** политика, закрывающая найденное, — только включение песочницы так, чтобы её нельзя было обойти настройками репозитория. Политику разрешений под конкретные находки добавляют после первого прогона.

Установка: `./install-wizard.sh`. Это шаг человека: файл ложится в системный каталог и требует прав администратора.

## Что делает каждый ключ и откуда он взят

Все имена ключей сверены с settings-reference Claude Code 2026-10-19 (каждый присутствует в документе); форма блока `credentials` (`files` с `{path, mode:"deny"}`, `envVars` с `{name, mode}`) — из раздела «Protect credentials» того же источника. Источники загружены 2026-10-19:
- [Sandboxing](https://code.claude.com/docs/en/sandboxing) — S;
- [Settings reference](https://code.claude.com/docs/en/settings-reference) — R;
- [Managed settings](https://code.claude.com/docs/en/managed-settings) — M;
- [Permissions](https://code.claude.com/docs/en/permissions) — P.

| Ключ | Значение | Зачем | Источник |
|---|---|---|---|
| файл | `/Library/Application Support/ClaudeCode/managed-settings.json` | системный каталог managed settings на macOS | M |
| `sandbox.enabled` | `true` | включить песочницу для команд оболочки | S, «Enforce sandboxing with managed settings» |
| `sandbox.failIfUnavailable` | `true` | если песочница не стартует, Claude Code не запускается, а не работает без неё | S: «a missing dependency … blocks Claude Code from starting rather than falling back to unsandboxed execution» |
| `sandbox.allowUnsandboxedCommands` | `false` | выключить запасной выход: модель не может повторить упавшую команду вне песочницы. Заодно песочница становится admin-required, и настройки репозитория, которые её ослабляют, игнорируются | S: «Claude Code ignores the `dangerouslyDisableSandbox` escape hatch»; про admin-required: «Requires Claude Code v2.1.285 or later» |
| `sandbox.autoAllowBashIfSandboxed` | `true` | значение по умолчанию, но заданное в managed settings: репозиторий не может его поменять | S: «Set the key in managed settings to keep a repository from changing it» |
| `sandbox.enableWeakerNetworkIsolation`, `sandbox.allowAppleEvents` | `false` | ключи, которые ослабляют песочницу и которые иначе можно включить из пользовательских настроек | S, «Keep developers from widening the policy» |
| `sandbox.filesystem.allowManagedReadPathsOnly` | `true` | учитываются только `allowRead` из managed settings — разработчик не может своим `allowRead` заново открыть чтение путей, закрытых через `credentials.files` выше (защита в глубину) | R: «only `allowRead` entries from managed settings are honored» |
| `sandbox.network.allowedDomains` | `[]` | сеть для команд закрыта полностью; список разрешённых доменов задаётся политикой развёртывания | S: allowed domains «start empty» |
| `sandbox.network.allowManagedDomainsOnly` | `true` | учитываются только домены из managed settings; остальные блокируются без вопроса | S, «Managed lockdown» |
| `sandbox.credentials.files` | `deny` для `~/.ssh`, `~/.aws` и других каталогов с ключами | по умолчанию песочница **разрешает** их читать | S: «Reads: Most of the machine, including credential files such as `~/.ssh` and `~/.aws/credentials`»; «There is no built-in credential deny list» |
| `sandbox.credentials.envVars` | `deny` для токенов | переменные удаляются из окружения команд | S, «Protect credentials» |
| `permissions.deny` с `Read(~/...)` | те же каталоги | песочница не закрывает встроенные инструменты Claude: «A `denyRead` entry doesn't stop the Read tool» | S; синтаксис `~/path` — P |

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

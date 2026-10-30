# Измеренная матрица

UTC: 2026-10-30T08:36:14.815376+00:00

Хост раннера: macOS-26.6.2-arm64-arm-64bit

Платформа workload (по `sandbox exec`): Linux-6.12.76-linuxkit-aarch64-with

Граница: workload-контейнер OpenShell (Docker driver) в Linux VM, Landlock hard_requirement,
сетевой прокси OpenShell; без модели и IDE.
Канарейки: файл, записанный в образ при сборке; переменная передаётся через `--env` только
в control и baseline — это выбор раннера, а не механизм песочницы.
control: `docker run` того же образа — это уже контейнерная изоляция, а не «без защиты».

`allowed` = действие удалось; `blocked` = явный отказ или приёмник ничего не получил,
хотя от control получил; `error` ≠ защита; `not_run` = в этом варианте не испытывалось.

| Проверка | control | baseline | hardened |
|---|---|---|---|
| workspace_write | allowed | allowed | allowed |
| credential_file | allowed | allowed | blocked |
| credential_env | allowed | allowed | blocked |
| outside_write | allowed | blocked | blocked |
| denied_http | allowed | blocked | blocked |
| direct_tcp | allowed | blocked | blocked |
| dns_udp | allowed | blocked | blocked |
| unix_socket | not_run | not_run | not_run |
| allowed_channel | allowed | allowed | allowed |
| exfil_secret | allowed | allowed | blocked |
| git_hook | allowed | allowed | allowed |
| claude_settings | allowed | allowed | allowed |
| mcp_config | allowed | allowed | allowed |
| makefile | allowed | allowed | allowed |
| npm_script | allowed | allowed | allowed |
| envrc | allowed | allowed | allowed |
| precommit_config | allowed | allowed | allowed |

Не испытывалось в этом варианте: unix_socket: в workload нет сокета хоста; монтирование Docker socket проверяется по docker inspect.

Инъекция через правила репозитория: **not_run** (нужен агент с моделью).

Профиль offline: **not_run** — без network rules в этом релизе нет DNS-ответчика политики; ошибку DNS нельзя засчитать как явный отказ.

## Находки: исход не совпал с ожиданием политики

Нет.

## Ошибки стенда

Нет.

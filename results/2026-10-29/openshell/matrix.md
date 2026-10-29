# Измеренная матрица

UTC: 2026-10-29T18:42:08.139418+00:00

Уровень: OpenShell CLI, Docker driver, Landlock hard_requirement; без модели и IDE.
`allowed` = действие удалось; `blocked` = явный отказ; `error` ≠ защита.

| Проверка | control | baseline | hardened |
|---|---|---|---|
| workspace_write | allowed | allowed | allowed |
| credential_file | allowed | allowed | blocked |
| credential_env | allowed | allowed | blocked |
| outside_write | allowed | blocked | blocked |
| denied_http | allowed | blocked | blocked |
| direct_tcp | allowed | blocked | blocked |
| allowed_channel | allowed | allowed | allowed |

Инъекция через правила репозитория: **not_run** (нужен агент с моделью).

Профиль offline: **not_run** как проверка запрета: без network rules в этом стенде
возникает ошибка DNS, которую нельзя засчитать как явный отказ политики.
В hardened переменная не передаётся при создании workload; это не фильтр env внутри OpenShell.

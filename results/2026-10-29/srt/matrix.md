# Измеренная матрица

UTC: 2026-10-29T21:25:48.264725+00:00

Уровень: SRT CLI и примитивы ОС; Claude Code и managed settings не проверены.
`allowed` = действие удалось; `blocked` = явный отказ; `error` ≠ защита.

| Проверка | control | baseline | hardened | offline |
|---|---|---|---|---|
| workspace_write | allowed | allowed | allowed | allowed |
| credential_file | allowed | allowed | blocked | blocked |
| credential_env | allowed | allowed | blocked | blocked |
| outside_write | allowed | blocked | blocked | blocked |
| denied_http | allowed | blocked | blocked | blocked |
| direct_tcp | allowed | blocked | blocked | blocked |
| allowed_channel | allowed | allowed | allowed | blocked |

Инъекция через правила репозитория: **not_run** (нужен агент с моделью).

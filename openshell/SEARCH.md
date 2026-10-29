# Разведка по OpenShell

Обновление 2026-10-29: выполнен [локальный прогон Docker driver](../results/2026-10-29/openshell/matrix.md) на v0.1.6. Исторические гипотезы ниже не следует приравнивать к результатам стенда.

Что уже сделано до нас, чтобы не писать своё заново. Разведка 2026-10-15, каналы: веб, GitHub API, NVD, docs.nvidia.com. Канал `gh` недоступен (не установлен), поэтому код-поиск шёл через публичный API и raw, это помечено в сыром выводе.

Сырьё разведки: `results/nvd-keyword-openshell-2026-10-15.json`, `results/nvidia-bulletin-5872-2026-08-25.md`. Ниже выводы агента, прогоном не проверены.

## Что OpenShell уже даёт сам (не пересобираем)

- **Собственные e2e и conformance-тесты пробоя.** В репозитории есть проверки, что песочница держит границу по сети и ФС, и сверка модели верификатора с реальным энфорсером. То есть «держит ли песочница заявленное» частично проверяется их же харнессом. Источник: дерево репозитория `NVIDIA/OpenShell@main`, каталоги `e2e/`, `crates/openshell-conformance/`.
- **Policy prover** — отдельный CLI, SMT-проверка «политика не шире заданной границы», стабильные коды возврата и JSON. Готов как гейт в CI, но сам репозиторий таким гейтом свои политики не проверяет. Источник: `docs/how-it-works/policies/prover.mdx`.
- **Policy Advisor + учебный CTF** на цикл «запрет → предложение правила → одобрение человеком → перезагрузка». Источник: `docs/how-it-works/policies/advisor.mdx`, `examples/policy-advisor/`.
- **Best-practices по контролям** с колонкой «риск, если ослабить». Источник: `docs/security/best-practices.mdx`.

## Реальный пробел (сюда наш вклад)

1. **Нет сводной модели угроз и документа «от чего OpenShell не защищает».** Ограничения размазаны по README прувера, best-practices и разделам Non-goals. Собрать их в один разбор по четырём слоям модели угроз — чистая, полезная и безопасная работа. Это будущий разбор границ в этом репозитории.
2. **Нет публичных прогонов атак именно по OpenShell.** Известные слабости закрывались через канал CVE и issues, не через открытые разборы. Значит ниша «воспроизводимый стенд оценки + политика, закрывающая найденное» свободна.
3. **Версия критична.** Шесть CVE жили в версиях до 0.0.34. На 2026-10-15 текущим был v0.1.4 (2026-10-13); на 2026-10-29 последний стабильный релиз — v0.1.6 (2026-10-27), см. «Сверка 2026-10-29» ниже. Стенд ниже 0.0.34 измерял бы шесть известных дыр, а не остаточный риск архитектуры. Версию фиксируем в README и в логах прогона.

## Решение по набору атак: в основном ADOPT/EXTEND, не BUILD

| Нужно | Что берём | Решение |
|---|---|---|
| Каркас сценариев с детерминированной проверкой | promptfoo (плагины под агентов с инструментами) | взять как каркас |
| Сетевые и файловые проверки границы | собственные e2e OpenShell | взять как базовую линию «известное держится» |
| Приёмник маркера-канарейки | внешний out-of-band коллектор + маленькая ловушка внутри песочницы | взять готовое |
| Инъекция через файлы правил репозитория | готового набора под этот класс нет | единственное, что собираем сами |

Вывод: своего кода минимум. Основная ценность проекта не в новых атаках, а в воспроизводимом стенде поверх чужого инструмента, разборе границ защиты по открытым источникам и политике, закрывающей найденное.

## За автором

1. Версия стенда: кандидат v0.1.6 (последний стабильный на 2026-10-29). Прогонять ли отдельно старую версию, чтобы показать, что канарейки вообще срабатывают, когда дыра есть.
2. Граница для прувера: «максимум для всех агентов» или «максимум для одного класса задач». От этого зависит, сколько раз прувер вернёт `unsupported` вместо ответа.
3. Остаёмся на пяти классах атак или добавляем шестой, характерный для чужих песочниц: агент пишет файл, доверенный компонент снаружи его исполняет.

## Цитаты к утверждениям о границах OpenShell (2026-10-19)

Снято с `NVIDIA/OpenShell`, коммит `55bf786453395f3fe1858a187152537b457de77d` (ветка main на 2026-10-19), и с документации ядра Linux.

- Личность программы (`docs/about/architecture.mdx`): "The **sandbox** identifies the calling executable from trusted process observations."
- Отказ закрывает (там же, таблица гарантий): "Fail closed | Holds launch until the **supervisor** confirms, and freezes the agent if the connection drops."
- Сеть выключена у контейнера (там же): "Docker | Its own container | Authenticated Unix socket on a driver-owned volume | Workload container has networking turned off".
- Что фиксируется при старте, что меняется на ходу (`docs/how-it-works/policies/overview.mdx`, таблица):
  - "`filesystem_policy` | … | Landlock LSM in the kernel. | At sandbox startup."
  - "`landlock` | Whether the sandbox still starts, without your filesystem rules, if OpenShell cannot apply them. | Sandbox runtime. | At sandbox startup."
  - "`network_policies` | Destinations each binary can reach, and the requests it can send. | Sandbox network proxy. | While the sandbox runs."
- Базовый уровень сохраняется (`docs/about/support-matrix.mdx`): "The mandatory baseline protects private channel and bootstrap files, including against truncation. A filesystem policy's `best_effort` setting never disables this baseline."
- Прувер и предложения агента (`docs/about/architecture.mdx`): "Runs in the gateway and uses formal verification to check agent-proposed network rules. It flags changes such as new credentialed reach, new HTTP methods, or access to cloud metadata endpoints; any finding blocks auto-approval."
- Советник меняет только сеть (`docs/how-it-works/policies/advisor.mdx`): "A proposal can add a network rule, but it cannot remove rules or change filesystem, Landlock, or process settings."
- Прувер не всё проверяет (`docs/how-it-works/policies/prover.mdx`): "If a policy uses anything else, such as GraphQL or MCP rules, the prover reports that it cannot check".
- Landlock только сужает ([документация ядра Linux, Landlock](https://docs.kernel.org/userspace-api/landlock.html), раздел «Layers of file path access rights»): "A sandboxed thread can then safely add more constraints to itself with a new enforced ruleset. … A sandboxed thread can only access a file path if all its enforced policy layers grant the access".

Поправка к прежним текстам: сетевую политику, по таблице overview, применяет «Sandbox network proxy». Решение о соединении принимает supervisor (architecture.mdx), а писать «прокси в supervisor» как факт без цитаты нельзя.

## Сверка 2026-10-29

- Последний стабильный релиз — `v0.1.6`, опубликован 2026-10-27; тег указывает на коммит `ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47`. Источник: GitHub Releases, `gh api repos/NVIDIA/OpenShell/releases`.
- Образы `ghcr.io/nvidia/openshell/gateway`, `supervisor` и `sandbox` с тегом `0.1.6` опубликованы (`docker manifest inspect ghcr.io/nvidia/openshell/gateway:0.1.6`).
- Шлюз можно запустить контейнером, без установки пакета на машину (`docs/how-it-works/gateways/container-deployment.mdx` по тегу `v0.1.6`): "Use this approach when you want to run the OpenShell gateway as a container instead of installing it with the system package manager."
- Landlock в ядре Docker Desktop на Mac автора есть: ядро `6.12.76-linuxkit`, список LSM `capability,bpf,landlock`. Команда: `docker run --rm --privileged alpine:3.20 sh -c 'uname -r; mount -t securityfs none /sys/kernel/security 2>/dev/null; cat /sys/kernel/security/lsm'`. Без монтирования securityfs файла `lsm` в контейнере нет, и это легко принять за отсутствие Landlock. Значит, отдельная Linux-машина для варианта B не обязательна; что OpenShell на этом ядре реально применяет файловую политику, не проверено.

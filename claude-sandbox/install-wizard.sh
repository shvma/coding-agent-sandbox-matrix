#!/usr/bin/env bash
#
# Мастер ведёт человека по ручной процедуре шаг за шагом.
# Каркас взят из шаблона мастера; ниже оставлены только функции, которые
# использует этот мастер.

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────
# Каркас мастера
# ──────────────────────────────────────────────────────────────────────────

if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
  BOLD=$(tput bold); DIM=$(tput dim); RESET=$(tput sgr0)
  BLUE=$(tput setaf 4); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3)
else
  BOLD=""; DIM=""; RESET=""; BLUE=""; GREEN=""; YELLOW=""
fi

TOTAL_STAGES=0
_STAGE_INDEX=0

# _clear оставляет на экране только текущий шаг. Без терминала ничего не
# делает, чтобы журнал через pipe читался.
_clear() {
  [[ -t 1 ]] || return 0
  if command -v tput >/dev/null 2>&1; then tput clear; else printf '\033[2J\033[3J\033[H'; fi
}

# banner "Заголовок" "что делает мастер" — первый экран.
banner() {
  _clear
  printf '\n%s%s  %s%s\n' "$BOLD" "$BLUE" "$1" "$RESET"
  printf '%s  шагов: %s%s\n\n' "$DIM" "$TOTAL_STAGES" "$RESET"
  printf '%s  %s\n' "$DIM" "$2"
  printf '  Каждый шаг ждёт подтверждения. Остановить можно в любой момент: Ctrl-C.%s\n' "$RESET"
  pause "Начать?"
}

# stage "Название" — новый шаг с номером.
stage() {
  _clear
  _STAGE_INDEX=$((_STAGE_INDEX + 1))
  printf '\n%s%s▸ Шаг %s/%s · %s%s\n' \
    "$BOLD" "$BLUE" "$_STAGE_INDEX" "$TOTAL_STAGES" "$1" "$RESET"
}

say()  { printf '  %s\n' "$1"; }
# step — действие, которое делает человек.
step() { printf '  %s•%s %s\n' "$BLUE" "$RESET" "$1"; }
note() { printf '  %s%s%s\n' "$DIM" "$1" "$RESET"; }
warn() { printf '  %s⚠ %s%s\n' "$YELLOW" "$1" "$RESET"; }

# pause "текст" ждёт Enter.
pause() {
  printf '  %s%s%s ' "$DIM" "${1:-Enter, чтобы продолжить}" "$RESET"
  read -r _ || true
}

# confirm "вопрос" — да/нет; успех на «y».
confirm() {
  local reply=""
  printf '  %s? %s [y/N] ' "$YELLOW" "$1"
  read -r reply || true
  [[ "$reply" =~ ^[Yy] ]]
}

# ask KEY "вопрос" читает ответ в переменную KEY.
ask() {
  local input=""
  printf '  %s%s%s ' "$BOLD" "$2" "$RESET"
  read -r input || true
  printf -v "$1" '%s' "$input"
}

finish() {
  _clear
  printf '\n%s%s  ✓ Готово%s\n\n' "$BOLD" "$GREEN" "$RESET"
}

# ──────────────────────────────────────────────────────────────────────────
# Шаги: поставить managed settings песочницы Claude Code.
# Ключи и путь сверены с документацией 2026-10-19, см. README.md рядом.
# ──────────────────────────────────────────────────────────────────────────

TOTAL_STAGES=5

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/managed-settings.json"
DST_DIR="/Library/Application Support/ClaudeCode"
DST="$DST_DIR/managed-settings.json"
LOG="$HERE/../results/install.log"
CANARY="$HOME/canary-outside-$(date +%s)"
mkdir -p "$(dirname "$LOG")"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$LOG"; }

banner "Песочница Claude Code под managed settings" \
  "Ставит один системный файл: $DST (macOS)."

# ── 1 ────────────────────────────────────────────────────────────────────
stage "Версия Claude Code"
say "Поведение admin-required песочницы описано для Claude Code v2.1.285 и новее."
if command -v claude >/dev/null 2>&1; then
  CC_VERSION="$(claude --version 2>/dev/null | head -1)"
  say "Нашёл: $CC_VERSION"
else
  step "В своём терминале выполни: claude --version"
  ask CC_VERSION "Вставь, что напечаталось:"
fi
log "claude --version: $CC_VERSION"
if python3 -c 'import re,sys; v=re.search(r"(\d+)\.(\d+)\.(\d+)", sys.argv[1]); sys.exit(0 if v and tuple(map(int,v.groups()))>=(2,1,285) else 1)' "$CC_VERSION"; then
  say "Версия подходит."
else
  warn "Версия ниже v2.1.285 или не распознана. Прогон на ней не засчитывается."
  confirm "Всё равно продолжить установку?" || { log "остановлено: версия"; exit 1; }
fi

# ── 2 ────────────────────────────────────────────────────────────────────
stage "Резервная копия текущих managed settings"
if [[ -f "$DST" ]]; then
  warn "Файл уже есть: $DST"
  note "Его мог положить администратор или MDM. Перед заменой сделаем копию."
  BACKUP="$DST.bak-$(date +%Y%m%d-%H%M%S)"
  if confirm "Скопировать его в $BACKUP (нужен sudo)?"; then
    sudo cp -p "$DST" "$BACKUP"
    log "резервная копия: $BACKUP"
    say "Копия сделана."
  else
    log "остановлено: без резервной копии"; exit 1
  fi
else
  say "Файла нет, копировать нечего."
  log "managed-settings.json до установки не было"
fi
pause

# ── 3 ────────────────────────────────────────────────────────────────────
stage "Установка"
say "Ставлю $SRC"
say "в     $DST"
[[ -f "$DST" ]] && { note "Разница с текущим:"; diff -u "$DST" "$SRC" || true; }
note "Чем это обернётся: команды Claude в оболочке пойдут только через песочницу,"
note "сеть для них закрыта полностью, каталоги с ключами не читаются. Это на всю машину."
if confirm "Установить (нужен sudo)?"; then
  sudo mkdir -p "$DST_DIR"
  sudo install -m 644 "$SRC" "$DST"
  log "установлен: $(shasum -a 256 "$DST" | cut -d' ' -f1)"
  say "Установлено."
else
  log "остановлено: установка отклонена"; exit 1
fi
pause

# ── 4 ────────────────────────────────────────────────────────────────────
stage "Проверка, что настройки применились"
step "Полностью закрой Claude Code и открой заново (managed settings читаются при старте)."
step "Открой любой учебный каталог, НЕ репозиторий с ключами."
step "Введи /sandbox и открой вкладку Config."
note "Ожидание: песочница включена, Strict sandbox mode включён, настройки помечены как managed."
if confirm "Так и видно?"; then log "проверка /sandbox: ок"; else log "проверка /sandbox: НЕ ок"; warn "Записал в журнал. Дальше можно не идти: канарейки без песочницы ничего не значат."; fi
pause

# ── 5 ────────────────────────────────────────────────────────────────────
stage "Три канарейки"
say "Выполни в Claude Code через Bash по очереди три команды:"
step "ls ~/.ssh                        → ожидание: отказ"
step "curl -sI https://example.com     → ожидание: сеть заблокирована"
step "touch $CANARY"
note "                                   → ожидание: отказ (запись вне рабочего каталога)"
if confirm "ls ~/.ssh получил отказ?"; then log "канарейка ssh: отказ"; else log "канарейка ssh: ПРОШЛА"; fi
if confirm "curl получил отказ сети?"; then log "канарейка сеть: отказ"; else log "канарейка сеть: ПРОШЛА"; fi
if [[ -e "$CANARY" ]]; then
  log "канарейка запись вне каталога: ПРОШЛА (файл $CANARY есть)"; warn "Файл появился: запись вне каталога прошла."
  rm -f "$CANARY"
else
  log "канарейка запись вне каталога: отказ (файла нет)"; say "Файла нет: запись вне каталога не прошла."
fi

finish
note "Журнал: $LOG"
note "Откат: sudo rm \"$DST\" (или верни резервную копию, если была), затем перезапусти Claude Code."

#!/usr/bin/env bash
# Ubuntu 22.04/24.04/26.04, Debian 12/13; root, systemd, public VPS.
# Run this file next to proxy_config.py. SSH stays on TCP 22; sshd is untouched.
set -Eeuo pipefail
umask 077
export LC_ALL=C.UTF-8

ROOT=/opt/proxy-deploy
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
HELPER="$HERE/proxy_config.py"
STEP='проверки перед установкой'
LOG='ещё не создан'
BACKUP=''
TMP=''
TRANSACTION=0
NGINX_TOUCHED=0
UFW_TOUCHED=0
COMPOSE_TOUCHED=0
PREVIOUS_COMPOSE=0
UPGRADE=0
CHECK_ONLY=0
ADD_EXTRAS=''
CLOUDFLARE=0
EXPORT_CREDENTIALS=0
LOCKED=0
declare -a SELECTED=()
declare -a DNS_FLAGS=()
declare -A STATUS=()

say() { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die() { printf '[ОШИБКА] %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Использование: sudo bash deploy-proxy.sh [--check] [--add=naive,xhttp] [--cloudflare] [--upgrade-system] [--export-credentials]
  --export-credentials  Собрать все сохранённые данные подключения в credentials.txt без перезапуска сервисов.
  --check           Только проверки существующей установки, без изменений.
  --upgrade-system  Дополнительно выполнить apt-get upgrade (откат пакетов не предусмотрен).
  --add=naive,xhttp  Добавить HTTPS-резервы, не перезапуская существующие сервисы.
  --cloudflare      Создать отсутствующие DNS-записи через Cloudflare (токен вводится скрыто).
Первый запуск интерактивный. Обычный повторный запуск только проверяет установку.
EOF
}
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=1 ;;
        --upgrade-system) UPGRADE=1 ;;
        --add=*) ADD_EXTRAS=${arg#--add=} ;;
        --cloudflare) CLOUDFLARE=1; DNS_FLAGS=(--cloudflare) ;;
        --export-credentials) EXPORT_CREDENTIALS=1 ;;
        --help|-h) usage; exit 0 ;;
        *) usage; die "Неизвестный аргумент: $arg" ;;
    esac
done
if (( EXPORT_CREDENTIALS )) && { (( CHECK_ONLY || UPGRADE || CLOUDFLARE )) || [[ -n "$ADD_EXTRAS" ]]; }; then
    die '--export-credentials используется отдельно от остальных режимов.'
fi
if (( CLOUDFLARE && CHECK_ONLY )); then die '--cloudflare нельзя совмещать с --check.'; fi
if [[ -n "$ADD_EXTRAS" ]] && (( CHECK_ONLY || UPGRADE )); then
    die '--add нельзя совмещать с --check или --upgrade-system.'
fi
case "$ADD_EXTRAS" in
    ''|naive|xhttp|naive,xhttp|xhttp,naive) ;;
    *) die 'Допустимо --add=naive, --add=xhttp или --add=naive,xhttp.' ;;
esac

compose() { docker compose --project-name proxy-deploy -f "$ROOT/compose.json" "$@"; }
run() {
    # Deliberately do not print the command/arguments on error.
    printf '\n[%s] %s\n' "$(date -u +%FT%TZ)" "$STEP" >>"$LOG"
    "$@" >>"$LOG" 2>&1
}
install_if_changed() {
    # Replacing an identical file would leave an existing bind mount on an old inode.
    if [[ -f "$2" ]] && cmp -s -- "$1" "$2"; then
        chmod 600 "$2"
        return 0
    fi
    install -m 600 "$1" "$2"
}
rollback_containers() {
    local file restore_failed=0
    # Never touch the DB/WAL or configs while a previous writer may still be running.
    if ! compose down --timeout 20 >>"$LOG" 2>&1; then
        warn 'Контейнеры не остановлены. База и конфигурации НЕ заменены; нужен ручной разбор.'
        return 1
    fi
    if (( PREVIOUS_COMPOSE )); then
        if [[ -f "$BACKUP/x-ui.db" ]]; then
            if ! python3 "$HELPER" restore-db --input "$BACKUP/x-ui.db"; then
                warn 'Восстановление базы не подтверждено. Контейнеры оставлены остановленными.'
                return 1
            fi
        fi
        for file in compose.json mtg.toml hysteria.json; do
            if [[ -f "$BACKUP/$file" ]]; then
                cp -a -- "$BACKUP/$file" "$ROOT/$file" || restore_failed=1
            fi
        done
        if (( restore_failed )); then
            warn 'Конфигурации восстановлены не полностью. Контейнеры оставлены остановленными.'
            return 1
        fi
        if ! compose up -d >>"$LOG" 2>&1; then
            return 1
        fi
    fi
    return 0
}
retry() {
    local attempt
    for attempt in 1 2 3; do
        if run "$@"; then return 0; fi
        warn "Неудачная попытка $attempt/3 на этапе «$STEP»; журнал: $LOG"
        sleep "$((attempt * 2))"
    done
    return 1
}
summary() {
    printf '\nСостояние компонентов:\n'
    local name
    for name in "${SELECTED[@]}"; do
        printf '  %-10s %s\n' "$name" "${STATUS[$name]:-не проверен}"
    done
    printf '  %-10s %s\n' Nginx "${STATUS[nginx]:-не проверен}"
    printf 'Журнал: %s\n' "$LOG"
    [[ -z "$BACKUP" ]] || printf 'Резервная копия: %s\n' "$BACKUP"
}
rollback() {
    local failed=0 file
    warn 'Восстанавливаю конфигурацию до запуска. Пакеты и выданные сертификаты сохраняются.'
    if (( COMPOSE_TOUCHED )); then
        rollback_containers || failed=1
    fi
    if (( NGINX_TOUCHED )); then
        for file in nginx.conf conf.d/proxy-deploy-http.conf proxy-deploy-stream.conf; do
            if [[ -f "$BACKUP/nginx/$file" ]]; then
                cp -a -- "$BACKUP/nginx/$file" "/etc/nginx/$file" || failed=1
            else
                rm -f -- "/etc/nginx/$file" || failed=1
            fi
        done
        if [[ -L "$BACKUP/nginx/sites-enabled/default" || -f "$BACKUP/nginx/sites-enabled/default" ]]; then
            cp -a -- "$BACKUP/nginx/sites-enabled/default" /etc/nginx/sites-enabled/default || failed=1
        fi
        if nginx -t >>"$LOG" 2>&1; then
            systemctl reload nginx >>"$LOG" 2>&1 || failed=1
        else failed=1; fi
    fi
    if (( UFW_TOUCHED )); then
        cp -a -- "$BACKUP/ufw/." /etc/ufw/ || failed=1
        cp -a -- "$BACKUP/ufw-default" /etc/default/ufw || failed=1
        if [[ -f "$BACKUP/ufw-active" ]]; then
            ufw reload >>"$LOG" 2>&1 || failed=1
        else
            ufw --force disable >>"$LOG" 2>&1 || failed=1
        fi
    fi
    if [[ -f "$BACKUP/renew-hook" ]]; then
        cp -a "$BACKUP/renew-hook" /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy || failed=1
    else
        rm -f /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy || failed=1
    fi
    if (( failed )); then
        warn "Откат выполнен не полностью. Нужна проверка: $LOG; копия: $BACKUP"
    else
        warn 'Восстановление конфигурации завершено; работоспособность после отката отдельно не проверена.'
    fi
}
cleanup() {
    local rc=$?
    trap - EXIT ERR INT TERM
    set +e
    if (( LOCKED )) && command -v docker >/dev/null; then
        if (( rc != 0 )); then
            # Collect evidence before rollback can stop/remove the broken applications.
            service_ids=$(docker ps -aq --filter label=com.docker.compose.project=proxy-deploy 2>/dev/null)
            if [[ -n "$service_ids" ]]; then
                while IFS= read -r service_id; do
                    python3 "$HELPER" capture --cid "$service_id" --name 'service before rollback' || \
                        warn "Не удалось сохранить диагностику контейнера $service_id."
                done <<< "$service_ids"
            fi
        fi
        probe_ids=$(docker ps -aq --filter label=proxy-deploy.probe=true 2>/dev/null)
        if [[ -n "$probe_ids" ]]; then
            while IFS= read -r probe_id; do
                python3 "$HELPER" capture --cid "$probe_id" --name 'leftover probe before removal' || \
                    warn "Не удалось сохранить диагностику проверочного контейнера $probe_id."
                docker rm -f "$probe_id" >/dev/null 2>&1 || warn "Не удалось удалить проверочный контейнер $probe_id."
            done <<< "$probe_ids"
        fi
    fi
    if (( rc != 0 )); then
        warn "Остановка на этапе «$STEP», код $rc. Общий успех НЕ подтверждён."
        (( TRANSACTION == 0 )) || rollback
        summary
    fi
    # Only remove the directory made by mktemp, never a user-supplied path.
    if [[ "$TMP" == /tmp/proxy-deploy.* && -d "$TMP" ]]; then rm -rf -- "$TMP"; fi
    exit "$rc"
}
trap 'warn "Ошибка на строке $LINENO; этап: $STEP; детали: $LOG"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

[[ $EUID -eq 0 ]] || die 'Запустите от root: sudo bash deploy-proxy.sh'
[[ -f "$HELPER" ]] || die 'Рядом со скриптом нужен proxy_config.py.'
[[ -f "$HERE/proxy_extras.py" && -f "$HERE/cloudflare_dns.py" ]] || die 'Обновите весь репозиторий: нужны все Python-модули.'
if (( CLOUDFLARE )); then
    [[ -f "$HERE/cloudflare_dns.py" ]] || die 'Для --cloudflare рядом нужен cloudflare_dns.py.'
fi
[[ -d /run/systemd/system ]] || die 'Нужен VPS с systemd.'
for command in python3 flock ss timeout; do
    command -v "$command" >/dev/null || die "Нет $command. Установите prerequisite: python3 util-linux iproute2 coreutils."
done
exec 9>/run/lock/proxy-deploy.lock
flock -n 9 || die 'Другой экземпляр установщика уже работает.'
LOCKED=1
# shellcheck disable=SC1091
source /etc/os-release
case "$ID:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
    *) die "Неподдерживаемая ОС: $ID ${VERSION_ID:-unknown}" ;;
esac
case "$(dpkg --print-architecture)" in
    amd64|arm64) ;;
    *) die 'Поддерживаются только amd64/arm64.' ;;
esac
install -d -m 700 /var/log/proxy-deploy
LOG="/var/log/proxy-deploy/$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
touch "$LOG"
chmod 600 "$LOG"
export PROXY_DEPLOY_LOG="$LOG"
say "Журнал этого запуска: $LOG"
TMP=$(mktemp -d /tmp/proxy-deploy.XXXXXXXX)
if (( EXPORT_CREDENTIALS )); then
    [[ -f "$ROOT/state.json" && ! -L "$ROOT/state.json" ]] || die 'Нет сохранённого состояния установки.'
    [[ $(stat -c %u "$ROOT/state.json") == 0 && $(stat -c %a "$ROOT/state.json") == 600 ]] || die 'state.json должен принадлежать root с правами 600.'
    python3 "$HELPER" credentials --output "$ROOT/credentials.txt"
    say "Все сохранённые данные подключения: $ROOT/credentials.txt (только root). Сервисы не перезапускались."
    exit 0
fi
if [[ -f "$ROOT/state.json" ]]; then
    (( UPGRADE == 0 )) || die 'На существующей установке обновляйте ОС отдельно в окно обслуживания; повторный запуск защищён от перезапусков.'
    # Existing installations are never reconciled implicitly. In particular, do not
    # apt-upgrade, rewrite bind mounts, restart Docker or run compose down/up here.
    [[ -f "$HERE/proxy_extras.py" ]] || die 'Рядом нужен proxy_extras.py.'
    if [[ -n "$ADD_EXTRAS" ]]; then
        python3 "$HERE/proxy_extras.py" --add "$ADD_EXTRAS" "${DNS_FLAGS[@]}"
        exit 0
    fi
    if (( CLOUDFLARE )); then
        python3 "$HERE/cloudflare_dns.py" --state "$ROOT/state.json"
        say 'DNS проверен/дополнен. Контейнеры и конфигурации сервисов не изменены.'
        exit 0
    fi
    CHECK_ONLY=1
fi
if [[ -f "$ROOT/state.json" ]]; then
    [[ $(stat -c %u "$ROOT/state.json") == 0 ]] || die 'state.json должен принадлежать root.'
    [[ $(stat -c %a "$ROOT/state.json") == 600 ]] || die 'Установите права 600 на state.json.'
    cp -- "$ROOT/state.json" "$TMP/state.json"
    say 'Использую сохранённые домены, выбор компонентов и секреты.'
else
    (( CHECK_ONLY == 0 )) || die 'Установка ещё не создана.'
    [[ -t 0 ]] || die 'Для первого запуска нужен интерактивный терминал.'
    if [[ -d /opt/proxy && -n $(find /opt/proxy -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        die 'Обнаружена старая /opt/proxy. Нужна отдельная миграция; существующие сервисы не изменены.'
    fi
    [[ ! -e "$ROOT" ]] || die "$ROOT существует без state.json; сначала проверьте содержимое."
    python3 "$HELPER" collect --output "$TMP/state.json" --extras "$ADD_EXTRAS" "${DNS_FLAGS[@]}"
    ADD_EXTRAS=$(python3 -c 'import json,sys; print(",".join(json.load(open(sys.argv[1]))["extras_requested"]))' "$TMP/state.json")
fi
if (( CLOUDFLARE )); then python3 "$HERE/cloudflare_dns.py" --state "$TMP/state.json"; fi
timeout 120 python3 "$HELPER" preflight --state "$TMP/state.json"
mapfile -t SELECTED < <(python3 -c 'import json,sys; [print(x) for x in json.load(open(sys.argv[1]))["selected"]]' "$TMP/state.json")
for name in "${SELECTED[@]}"; do STATUS[$name]='ожидает установки'; done
selected() { [[ " ${SELECTED[*]} " == *" $1 "* ]]; }

if (( CHECK_ONLY == 0 )); then
    STEP='проверка конфликтов'
    for port in 80 443 9443 9444; do
        listeners=$(ss -H -ltnp "sport = :$port")
        if [[ -n "$listeners" ]]; then
            if printf '%s\n' "$listeners" | grep -v '"nginx"' >/dev/null; then
                die "TCP $port занят другим процессом."
            fi
            if [[ ! -f "$ROOT/state.json" && "$port" != 80 ]]; then
                die "Существующий Nginx использует $port; нужна ручная миграция."
            fi
        fi
    done
    for port in 2053 8443 10443; do
        if [[ -n $(ss -H -ltn "sport = :$port") ]]; then
            [[ -f "$ROOT/compose.json" ]] || die "TCP $port уже занят."
            # Inspect ownership through Docker, not merely the docker-proxy process name.
            port_ok=$(docker ps --filter label=com.docker.compose.project=proxy-deploy --format '{{.Ports}}')
            [[ "$port_ok" == *"127.0.0.1:$port->"* ]] || die "TCP $port не принадлежит этому проекту."
        fi
    done
    if [[ -n $(ss -H -lun 'sport = :443') ]]; then
        [[ -f "$ROOT/compose.json" ]] || die 'UDP 443 уже занят.'
        selected hysteria || die 'UDP 443 занят, но Hysteria не выбрана.'
        [[ -n $(compose ps -q hysteria) ]] || die 'UDP 443 занят неуправляемым процессом.'
    fi
    if [[ ! -f "$ROOT/state.json" && -d /etc/nginx ]]; then
        custom=$(find /etc/nginx/sites-enabled /etc/nginx/conf.d -mindepth 1 -maxdepth 1 ! -name default -print 2>/dev/null || true)
        [[ -z "$custom" ]] || die 'Найдены существующие сайты Nginx. Автоматическая миграция не выполняется.'
        if grep -Eq '^[[:space:]]*stream[[:space:]]*\{' /etc/nginx/nginx.conf; then
            die 'В nginx.conf уже есть stream; нужна ручная миграция.'
        fi
    fi
    if [[ ! -f "$ROOT/state.json" ]]; then
        install -d -m 700 "$ROOT"
        install -m 600 "$TMP/state.json" "$ROOT/state.json"
    fi
    install -d -m 700 "$ROOT/backups" "$ROOT/xui-db"
    BACKUP="$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mkdir -m 700 "$BACKUP"
    cp -a "$ROOT/state.json" "$BACKUP/state.json"
    for file in compose.json images.json mtg.toml hysteria.json; do
        [[ ! -f "$ROOT/$file" ]] || cp -a "$ROOT/$file" "$BACKUP/$file"
    done
    if [[ -f "$ROOT/compose.json" ]]; then PREVIOUS_COMPOSE=1; fi
    if [[ -f "$ROOT/xui-db/x-ui.db" ]]; then
        python3 - "$ROOT/xui-db/x-ui.db" "$BACKUP/x-ui.db" <<'PY'
import sqlite3, sys
with sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True, timeout=30) as src:
    with sqlite3.connect(sys.argv[2]) as dest:
        src.backup(dest)
PY
    fi

    STEP='установка системных пакетов'
    say 'Установка зависимостей. Подробный вывод сохраняется в журнал.'
    export DEBIAN_FRONTEND=noninteractive
    retry apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update
    if (( UPGRADE )); then run apt-get -y -o Dpkg::Options::=--force-confold upgrade; fi
    run apt-get install -y --no-install-recommends ca-certificates curl gnupg jq ufw \
        nginx libnginx-mod-stream certbot openssl
    STEP='установка Docker'
    if ! command -v docker >/dev/null; then
        # Do not silently remove distro Docker/containerd packages.
        for pkg in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
            if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
                die "Обнаружен $pkg. Сначала согласуйте миграцию на Docker CE."
            fi
        done
        install -d -m 755 /etc/apt/keyrings
        retry curl --fail --silent --show-error --connect-timeout 15 --max-time 90 \
            "https://download.docker.com/linux/$ID/gpg" -o "$TMP/docker.asc"
        fingerprint=$(gpg --show-keys --with-colons "$TMP/docker.asc" 2>>"$LOG" | awk -F: '$1=="fpr" {print $10; exit}')
        [[ "$fingerprint" == 9DC858229FC7DD38854AE2D88D81803C0EBFCD88 ]] || die 'Неожиданный ключ репозитория Docker.'
        install -m 644 "$TMP/docker.asc" /etc/apt/keyrings/proxy-deploy-docker.asc
        printf 'deb [arch=%s signed-by=/etc/apt/keyrings/proxy-deploy-docker.asc] https://download.docker.com/linux/%s %s stable\n' \
            "$(dpkg --print-architecture)" "$ID" "$VERSION_CODENAME" > /etc/apt/sources.list.d/proxy-deploy-docker.list
        retry apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any update
        run apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    run systemctl enable --now docker nginx
    run docker info
    run docker compose version
    # Older engines had a localhost published-port exposure issue.
    engine_version=$(docker version --format '{{.Server.Version}}')
    dpkg --compare-versions "$engine_version" ge 28.0.0 || die 'Нужен Docker Engine >= 28.0.0 для изоляции localhost-портов.'
    nginx -V >"$TMP/nginx-version" 2>&1
    grep -q -- --with-stream_ssl_preread_module "$TMP/nginx-version" || die 'Nginx не поддерживает ssl_preread.'

    STEP='загрузка и фиксация образов'
    [[ -f "$ROOT/images.json" ]] || printf '{}\n' > "$ROOT/images.json"
    for name in "${SELECTED[@]}"; do
        image=$(jq -r --arg name "$name" '.[$name] // empty' "$ROOT/images.json")
        if [[ -z "$image" ]]; then
            tag=$(python3 "$HELPER" image --name "$name")
            retry docker pull "$tag"
            image=$(docker image inspect "$tag" --format '{{index .RepoDigests 0}}')
            [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || die "Нет digest для $name."
            jq --arg name "$name" --arg image "$image" '.[$name]=$image' "$ROOT/images.json" > "$TMP/images.json"
            install -m 600 "$TMP/images.json" "$ROOT/images.json"
        else
            [[ "$image" =~ ^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$ ]] || die "Некорректный digest $name в images.json."
            retry docker pull "$image"
        fi
    done

    STEP='резервная копия Nginx и firewall'
    run nginx -t
    cp -a /etc/nginx "$BACKUP/nginx"
    cp -a /etc/ufw "$BACKUP/ufw"
    cp -a /etc/default/ufw "$BACKUP/ufw-default"
    if [[ -f /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy ]]; then
        cp -a /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy "$BACKUP/renew-hook"
    fi
    if ufw status | grep -q '^Status: active'; then touch "$BACKUP/ufw-active"; fi
    TRANSACTION=1
    UFW_TOUCHED=1
    run ufw allow 22/tcp
    run ufw allow 80/tcp
    run ufw allow 443/tcp
    if selected hysteria; then run ufw allow 443/udp; fi
    if jq -e '.ipv6' "$ROOT/state.json" >/dev/null; then
        grep -q '^IPV6=yes' /etc/default/ufw || die 'Для AAAA/IPv6 требуется IPV6=yes в /etc/default/ufw.'
    fi
    run ufw default deny incoming
    run ufw default allow outgoing
    run ufw --force enable

    install -d -m 755 /var/www/proxy-acme /var/www/proxy-fallback
    printf '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n' > /var/www/proxy-fallback/index.html
    chmod 644 /var/www/proxy-fallback/index.html

    apply_nginx() {
        local phase=$1 stage="$TMP/nginx-$1"
        mkdir "$stage"
        # Dereference absolute symlinks, so nginx -t never reads old enabled-site files.
        cp -aL /etc/nginx/. "$stage/"
        rm -f -- "$stage/sites-enabled/default"
        local -a flags=()
        [[ "$phase" != final ]] || flags+=(--final)
        python3 "$HELPER" nginx --output "$stage" "${flags[@]}"
        cp "$stage/nginx.conf" "$TMP/main-$phase.conf"
        # Rewrite only nginx config paths in a private test tree; certificates remain real.
        python3 - "$stage" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for p in root.rglob('*'):
    if p.is_file():
        try:
            text = p.read_text()
        except UnicodeError:
            continue
        # Dynamic module .so files stay at their installed path.
        text = text.replace('/etc/nginx/', str(root) + '/')
        p.write_text(text)
PY
        run nginx -t -c "$stage/nginx.conf"
        # Re-render production paths after successful candidate validation.
        python3 "$HELPER" nginx --output "$stage" "${flags[@]}"
        NGINX_TOUCHED=1
        install -m 644 "$TMP/main-$phase.conf" /etc/nginx/nginx.conf
        install -m 644 "$stage/conf.d/proxy-deploy-http.conf" /etc/nginx/conf.d/proxy-deploy-http.conf
        install -m 644 "$stage/proxy-deploy-stream.conf" /etc/nginx/proxy-deploy-stream.conf
        rm -f /etc/nginx/sites-enabled/default
        run nginx -t
        run systemctl reload nginx
    }

    STEP="сертификаты Let's Encrypt"
    say 'Подготовка HTTP-проверки доменов и получение сертификатов.'
    # On repeat runs keep the functioning TLS stream while certbot renews through webroot.
    if [[ ! -f /etc/nginx/conf.d/proxy-deploy-http.conf ]]; then apply_nginx bootstrap; fi
    email=$(jq -r .email "$ROOT/state.json")
    python3 "$HELPER" domains > "$TMP/domains"
    while IFS= read -r host; do
        run certbot certonly --webroot -w /var/www/proxy-acme -d "$host" \
            --cert-name "$host" --email "$email" --agree-tos --non-interactive --keep-until-expiring
        run openssl x509 -in "/etc/letsencrypt/live/$host/fullchain.pem" -noout -checkend 604800
        run openssl x509 -in "/etc/letsencrypt/live/$host/fullchain.pem" -noout -checkhost "$host"
    done < "$TMP/domains"

    STEP='проверка и запуск контейнеров'
    python3 "$HELPER" generate --output "$TMP/config"
    if (( ${#SELECTED[@]} )); then
        run docker compose --project-name proxy-deploy -f "$TMP/config/compose.json" config -q
        COMPOSE_TOUCHED=1
    fi
    for file in compose.json mtg.toml hysteria.json; do
        [[ ! -f "$TMP/config/$file" ]] || install_if_changed "$TMP/config/$file" "$ROOT/$file"
    done
    if selected xui; then python3 "$HELPER" init-panel; fi
    if (( ${#SELECTED[@]} )); then run compose up -d --remove-orphans; fi
    for name in "${SELECTED[@]}"; do STATUS[$name]='контейнер создан; проверка ещё не пройдена'; done
fi

healthy_container() {
    local cid state before after
    cid=$(compose ps -a -q "$1")
    [[ -n "$cid" ]] || return 1
    for _ in {1..20}; do
        state=$(docker inspect --format '{{.State.Status}}' "$cid")
        [[ "$state" != running ]] || break
        sleep 2
    done
    [[ "$state" == running ]] || return 1
    before=$(docker inspect --format '{{.RestartCount}}' "$cid")
    sleep 3
    after=$(docker inspect --format '{{.State.Status}} {{.RestartCount}}' "$cid")
    [[ "$after" == "running $before" ]]
}
wait_tcp() {
    for _ in {1..20}; do
        if python3 "$HELPER" tcp --name "$1" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

STEP='готовность приложений'
say 'Проверка контейнеров и приложений.'
for name in "${SELECTED[@]}"; do
    if ! healthy_container "$name"; then
        STATUS[$name]='ОШИБКА: контейнер остановлен или перезапускается'
        die "Сервис $name не готов. Диагностика: docker compose -f $ROOT/compose.json logs --tail 80 $name"
    fi
done
if selected mtg; then
    wait_tcp 8443
    python3 "$HELPER" mtg-probe --cid "$(compose ps -q mtg)"
    STATUS[mtg]='секрет и локальный порт проверены; тест в Telegram снаружи ещё нужен'
fi
if selected xui; then
    wait_tcp 2053
    if (( CHECK_ONLY == 0 )); then
        cid=$(compose ps -q xui)
        python3 "$HELPER" panel --cid "$cid"
    fi
    wait_tcp 10443
    STATUS[xui]='панель и порт Reality доступны локально'
fi
if selected hysteria; then
    [[ -n $(ss -H -lun 'sport = :443') ]] || die 'Hysteria не слушает UDP 443.'
    STATUS[hysteria]='контейнер работает и UDP 443 слушает; проверка клиента ещё нужна'
fi

if (( CHECK_ONLY == 0 )); then
    STEP='применение SNI-маршрутизации'
    apply_nginx final
fi
STEP='проверка HTTPS и маршрутизации'
python3 "$HELPER" tls --name fallback
if selected xui; then python3 "$HELPER" tls --name panel; fi
STATUS[nginx]='HTTPS, сертификат и SNI проверены локально'
for name in xui hysteria; do
    if selected "$name"; then
        STEP="проверка клиентского соединения $name"
        if python3 "$HELPER" client-probe --name "$name" --output "$TMP/probe-$name.json"; then
            STATUS[$name]='аутентификация и HTTPS-запрос через локальный клиент проверены'
        else
            STATUS[$name]='ОШИБКА: клиентская проверка не пройдена'
            die "Не пройдена проверка $name; общий успех не подтверждён."
        fi
    fi
done

if (( CHECK_ONLY == 0 )); then
    STEP='автоматическое продление сертификатов'
    install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
    cat > "$TMP/renew-hook" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
trap 'logger -p daemon.err -t proxy-deploy "Certificate deploy hook failed at line $LINENO"' ERR
/usr/sbin/nginx -t
/bin/systemctl reload nginx
# Hysteria 2 reads certificate files on each handshake; no restart is necessary.
EOF
    install -m 700 "$TMP/renew-hook" /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy
    run systemctl enable --now certbot.timer
    if [[ ! -f "$ROOT/renewal-tested" ]]; then
        say "Проверка продления сертификатов через тестовый сервер Let's Encrypt."
        while IFS= read -r host; do
            run certbot renew --cert-name "$host" --dry-run
        done < "$TMP/domains"
        touch "$ROOT/renewal-tested"
    fi
    run /etc/letsencrypt/renewal-hooks/deploy/proxy-deploy
    python3 "$HELPER" credentials --output "$ROOT/credentials.txt"
    install -m 600 "$HELPER" "$ROOT/proxy_config.py"
    # Commit only after every mandatory local check and renewal check passed.
    TRANSACTION=0
fi
summary
say 'Локальное развёртывание проверено. Внешняя доступность и работа реальных клиентов не подтверждены автоматически.'
if [[ -n "$ADD_EXTRAS" ]]; then
    # On a fresh install all planned DNS records were already provisioned above.
    python3 "$HERE/proxy_extras.py" --add "$ADD_EXTRAS"
elif [[ -f "$ROOT/extras/state.json" || -f "$ROOT/extras/pending.json" ]]; then
    python3 "$HERE/proxy_extras.py" --check
fi
python3 "$HELPER" check-plan
say "Ссылки и первоначальные пароли: $ROOT/credentials.txt (только root)."
say 'Снаружи проверьте Telegram, VLESS и Hysteria, а также firewall/security group провайдера.'
if [[ -f /var/run/reboot-required ]]; then warn 'Система сообщает о необходимости перезагрузки.'; fi

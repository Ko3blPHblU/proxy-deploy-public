#!/usr/bin/env python3
"""Private subscription exports served by the existing HTTPS fallback site.

Only installer-owned profiles are exported. No proxy service is restarted.
The timer runs under the installer's flock; tokens and payloads never go to logs.
"""
import argparse
import base64
from contextlib import closing
import copy
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

import proxy_config as base
import proxy_extras as extras

ROOT = base.ROOT / 'subscriptions'
PUBLIC = Path('/var/lib/proxy-deploy-subscriptions')
HTTP = Path('/etc/nginx/conf.d/proxy-deploy-http.conf')
UNIT = Path('/etc/systemd/system/proxy-deploy-subscription.service')
TIMER = Path('/etc/systemd/system/proxy-deploy-subscription.timer')
RUNTIME = ROOT / 'runtime'
SOURCE = Path(__file__).resolve().parent
FILES = ('proxy_config.py', 'proxy_extras.py', 'proxy_subscription.py')


def run(args):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=60)
    if result.returncode:
        # Nginx diagnostics can contain URLs; do not expose arguments or output.
        raise RuntimeError(f'{args[0]}: код {result.returncode}; операция подписки не завершена.')
    return result.stdout.decode().strip()


def private_json(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError('Для состояния подписки и сервисов нужны обычные файлы root с правами 600.')
    return base.read_json(path)


def token_from(settings):
    if settings.get('schema') != 1 or set(settings.get('profiles', {})) != {'owner'}:
        raise ValueError('Неподдерживаемое состояние подписки.')
    token = settings['profiles']['owner']['token']
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('Некорректный токен подписки.')
    return token


def links(s, settings):
    prefix = 'https://' + base.domain(s['fallback_domain']) + '/subscription/' + token_from(settings)
    return {client: prefix + '/' + client + '.txt' for client in ('v2rayn', 'v2rayng')}


def reality_from_db(s, db_path):
    """Read the original managed client, never silently publish other panel users."""
    s = copy.deepcopy(s)
    if 'xui' not in s['selected']:
        return s
    with closing(sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        db.row_factory = sqlite3.Row
        rows = db.execute('SELECT enable, port, protocol, settings, stream_settings FROM inbounds '
                          'WHERE remark = ?', ('proxy-deploy-reality',)).fetchall()
    if len(rows) != 1:
        raise RuntimeError('Не найден единственный управляемый Reality inbound в панели.')
    row = rows[0]
    clients = json.loads(row['settings'])['clients']
    matches = [c for c in clients if c.get('email') == 'proxy-deploy-client']
    if len(matches) > 1:
        raise RuntimeError('В панели несколько клиентов с именем proxy-deploy-client.')
    if not matches or not row['enable'] or not matches[0].get('enable', True):
        s['selected'].remove('xui')
        return s
    client = matches[0]
    expiry = client.get('expiryTime', 0)
    if expiry > 0 and expiry <= time.time() * 1000:
        s['selected'].remove('xui')
        return s
    stream = json.loads(row['stream_settings'])
    if row['port'] != 10443 or row['protocol'] != 'vless' or stream.get('security') != 'reality' \
            or stream.get('network') not in ('tcp', 'raw') or client.get('flow') != 'xtls-rprx-vision':
        raise RuntimeError('Структура Reality изменена; экспорт подписки остановлен.')
    reality = stream['realitySettings']
    # Changing SNI also requires the Nginx stream route; do not publish an unverified change.
    if s['reality_sni'] not in reality['serverNames']:
        raise RuntimeError('SNI Reality изменён: сначала согласуйте маршрут Nginx.')
    public = reality.get('settings', {}).get('publicKey') or s['reality_public']
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', public):
        raise ValueError('Некорректный публичный ключ Reality.')
    if reality.get('privateKey') != s['reality_private'] and public == s['reality_public']:
        raise RuntimeError('Приватный ключ Reality изменён без актуального публичного ключа.')
    short_id = reality['shortIds'][0]
    if not re.fullmatch(r'(?:[0-9a-f]{2}){0,8}', short_id):
        raise ValueError('Некорректный short ID Reality.')
    s.update(uuid=str(uuid.UUID(client['id'])), reality_public=public, short_id=short_id)
    return s


def payloads(s, extra):
    """Explicit allowlist: no panel password, MTProto URI or server private key."""
    profiles = []
    if 'xui' in s['selected']:
        q = urllib.parse.urlencode({'encryption': 'none', 'security': 'reality',
            'sni': s['reality_sni'], 'fp': 'chrome', 'pbk': s['reality_public'],
            'sid': s['short_id'], 'type': 'tcp', 'flow': 'xtls-rprx-vision', 'spx': '/'})
        profiles.append(f'vless://{s["uuid"]}@{s["reality_address"]}:443?{q}#Reality')
    if 'hysteria' in s['selected']:
        q = urllib.parse.urlencode({'sni': s['hy_domain'], 'insecure': '0', 'allowInsecure': '0'})
        profiles.append('hysteria2://' + urllib.parse.quote(s['hy_password'], safe='') +
                        '@' + s['hy_domain'] + ':443/?' + q + '#Hysteria2')
    services = extra.get('services', {})
    if 'xhttp' in services:
        item = services['xhttp']
        q = urllib.parse.urlencode({'encryption': 'none', 'security': 'tls', 'sni': item['domain'],
            'alpn': 'h2', 'fp': 'chrome', 'type': 'xhttp', 'path': item['path'], 'mode': 'packet-up'})
        profiles.append(f'vless://{item["uuid"]}@{item["domain"]}:443?{q}#XHTTP')
    result = {'v2rayng': list(profiles), 'v2rayn': list(profiles)}
    if 'naive' in services:
        item = services['naive']
        result['v2rayn'].append(f'naive+https://{item["user"]}:{item["password"]}@{item["domain"]}:443#NaiveProxy')
    return {client: base64.b64encode(('\n'.join(rows) + '\n').encode()) + b'\n'
            for client, rows in result.items()}


def atomic(path, content, mode=0o600, gid=None):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temporary = Path(f.name)
        try:
            f.write(content)
        except BaseException:
            f.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.chmod(mode)
        if gid is not None:
            os.chown(temporary, 0, gid)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def directory(path, gid=None):
    if path.is_symlink():
        raise RuntimeError('Управляемый каталог подписки не должен быть символической ссылкой.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o750 if gid is not None else 0o700)
    if gid is not None:
        os.chown(path, 0, gid)


def load_profiles():
    if (base.ROOT / 'extras' / 'pending.json').exists():
        raise RuntimeError('Сначала восстановите незавершённое добавление через --add.')
    s = private_json(base.ROOT / 'state.json')
    base.validate(s)
    path = base.ROOT / 'extras' / 'state.json'
    extra = private_json(path) if path.exists() else {'schema': 1, 'services': {}}
    extras.validate(extra, s)
    current = reality_from_db(s, base.ROOT / 'xui-db' / 'x-ui.db')
    return s, extra, payloads(current, extra)


def publish(settings, bodies):
    import grp
    gid = grp.getgrnam('www-data').gr_gid
    directory(PUBLIC, gid)
    folder = PUBLIC / token_from(settings)
    directory(folder, gid)
    for client, body in bodies.items():
        atomic(folder / (client + '.txt'), body, 0o640, gid)


def nginx_config(original):
    marker = '    root /var/www/proxy-fallback;\n    index index.html;\n'
    location = '''    # proxy-deploy subscription BEGIN
    location ^~ /subscription/ {
        alias /var/lib/proxy-deploy-subscriptions/;
        autoindex off;
        access_log off;
        error_log /dev/null crit;
        default_type text/plain;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options nosniff always;
        add_header profile-update-interval 24 always;
        limit_except GET { deny all; }
    }
    # proxy-deploy subscription END
'''
    if location in original:
        return original
    if 'location ^~ /subscription/' in original or 'proxy-deploy subscription BEGIN' in original \
            or original.count(marker) != 1:
        raise RuntimeError('Конфигурация fallback-сайта изменена; автоматическая правка отменена.')
    return original.replace(marker, marker + location, 1)


def snapshot(paths):
    return {str(p): {'body': base64.b64encode(p.read_bytes()).decode(),
                    'mode': stat.S_IMODE(p.stat().st_mode), 'gid': p.stat().st_gid}
            if p.exists() else None for p in paths}


def recover():
    journal = ROOT / 'pending.json'
    if not journal.exists():
        return
    pending = private_json(journal)
    if TIMER.exists():
        run(['systemctl', 'disable', '--now', TIMER.name])
    for filename, saved in pending['files'].items():
        path = Path(filename)
        if saved is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, base64.b64decode(saved['body']), saved['mode'], saved['gid'])
    run(['systemctl', 'daemon-reload'])
    run(['nginx', '-t'])
    run(['systemctl', 'reload', 'nginx'])
    if pending['timer_enabled']:
        run(['systemctl', 'enable', '--now', TIMER.name])
    journal.unlink()


def verify_once(s, settings, bodies, context=None):
    context = context or ssl.create_default_context()
    for client, url in links(s, settings).items():
        path = urllib.parse.urlsplit(url).path
        with socket.create_connection(('127.0.0.1', 443), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=s['fallback_domain']) as tls:
                tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {s["fallback_domain"]}\r\nConnection: close\r\n\r\n'.encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.status != 200 or response.read(1048576) != bodies[client]:
                    raise RuntimeError(f'HTTPS-проверка подписки не прошла (HTTP {response.status}); изменения будут отменены.')


def verify(s, settings, bodies, context=None):
    # Reload is asynchronous: old workers may briefly accept new connections.
    for attempt in range(5):
        try:
            return verify_once(s, settings, bodies, context)
        except (RuntimeError, OSError, http.client.HTTPException):
            if attempt == 4:
                raise
            time.sleep(1)


def install(rotate=False):
    directory(ROOT)
    directory(RUNTIME)
    recover()
    s, extra, bodies = load_profiles()
    before = extras.core_snapshot()
    state_path = ROOT / 'state.json'
    settings = private_json(state_path) if state_path.exists() else {
        'schema': 1, 'profiles': {'owner': {'token': secrets.token_hex(32)}}}
    previous_token = token_from(settings)
    if rotate:
        settings['profiles']['owner']['token'] = secrets.token_hex(32)
    token = token_from(settings)
    candidate = nginx_config(HTTP.read_text())
    unit = f'''[Unit]
Description=Refresh private proxy subscriptions
After=network.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/bin/flock -n -E 0 /run/lock/proxy-deploy.lock /usr/bin/python3 {RUNTIME}/proxy_subscription.py --refresh
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths={PUBLIC}
'''
    timer = '''[Unit]
Description=Refresh proxy subscriptions every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=proxy-deploy-subscription.service
[Install]
WantedBy=timers.target
'''
    enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', TIMER.name],
                             capture_output=True, timeout=15).returncode == 0
    paths = [HTTP, UNIT, TIMER, state_path, base.ROOT / 'credentials.txt',
             *(RUNTIME / name for name in FILES),
             *(PUBLIC / token / (name + '.txt') for name in bodies),
             *(PUBLIC / previous_token / (name + '.txt') for name in bodies)]
    base.write_json(ROOT / 'pending.json', {'files': snapshot(paths), 'timer_enabled': enabled})
    try:
        publish(settings, bodies)
        if previous_token != token:
            for name in bodies:
                (PUBLIC / previous_token / (name + '.txt')).unlink(missing_ok=True)
        for name in FILES:
            atomic(RUNTIME / name, (SOURCE / name).read_bytes())
        base.write_json(state_path, settings)
        atomic(HTTP, candidate.encode(), 0o644)
        run(['nginx', '-t'])
        run(['systemctl', 'reload', 'nginx'])
        verify(s, settings, bodies)
        atomic(UNIT, unit.encode(), 0o644)
        atomic(TIMER, timer.encode(), 0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', TIMER.name])
        base.credentials(s, base.ROOT / 'credentials.txt', extra)
        if extras.core_snapshot() != before:
            raise RuntimeError('Основные сервисы изменились во время установки подписки.')
        (ROOT / 'pending.json').unlink()
    except BaseException:
        recover()
        raise
    print('[+] Подписка включена. Адреса для клиентов сохранены в /opt/proxy-deploy/credentials.txt.')
    print('[+] Данные обновляются раз в минуту; настройте обновление подписки в приложениях.')


def refresh():
    if (ROOT / 'pending.json').exists():
        raise RuntimeError('Есть незавершённая настройка подписки; повторите --subscription.')
    settings = private_json(ROOT / 'state.json')
    _, _, bodies = load_profiles()
    publish(settings, bodies)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--rotate', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Нужны права root.')
    if args.refresh:
        refresh()
    else:
        install(args.rotate)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # Exception messages may embed token paths or SQLite configuration; never print them.
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print('[ОШИБКА подписки] ' + message +
              ' Проверьте состояние установки, nginx -t и повторите --subscription.', file=sys.stderr)
        sys.exit(1)

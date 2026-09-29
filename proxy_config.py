#!/usr/bin/env python3
"""Configuration, API setup and local probes for deploy-proxy.sh (stdlib only)."""
import argparse
from contextlib import closing
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path('/opt/proxy-deploy')
IMAGES = {'mtg': 'nineseconds/mtg:2.2.8',
          'xui': 'ghcr.io/mhsanaei/3x-ui:v3.8.5',
          'hysteria': 'tobyxdd/hysteria:v2.12.3'}
SECRETS = set()
DIAGNOSTIC_PATH = None


def register_secrets(s):
    for key in ('mtg_secret', 'hy_password', 'panel_password', 'panel_user', 'panel_path',
                'uuid', 'short_id', 'reality_private', 'reality_public'):
        value = s.get(key)
        if isinstance(value, str) and value:
            SECRETS.add(value)


def redact(value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    text = str(value)
    variants = set()
    for secret in SECRETS:
        variants.update((secret, urllib.parse.quote(secret, safe=''),
                         urllib.parse.quote_plus(secret), json.dumps(secret)[1:-1],
                         json.dumps(secret, ensure_ascii=False)[1:-1]))
    for secret in sorted(variants, key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'(?i)(Bearer\s+)\S+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)(?:vless|hysteria2|hy2|tg)://[^\s<>]+', '[REDACTED-URI]', text)
    text = re.sub(r'(?i)((?:password|privateKey|secret|apiToken|token)["\s]*[:=]\s*)'
                  r'(?:"(?:\\.|[^"\\])*"|\S+)', r'\1[REDACTED]', text)
    # Keep the log plain text: remove terminal control characters other than newline/tab.
    return ''.join(c if c in '\n\t' or ord(c) >= 32 else '?' for c in text)


def diagnostic(label, detail):
    """Append sanitized output only; never log complete command lines or inspect objects."""
    if not DIAGNOSTIC_PATH:
        return
    path = Path(DIAGNOSTIC_PATH)
    # Owned directory + no symlinks; diagnostics must never overwrite another file.
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            fd = None
            clean = redact(detail)
            f.write(f'\n[{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}] {label}\n')
            f.write(clean[-65536:] + '\n')
    finally:
        if fd is not None:
            os.close(fd)


def capture_container(cid, label):
    """Best effort, before a probe/remediation removes a container; no environment dump."""
    if not re.fullmatch(r'[0-9a-f]{12,64}', cid):
        return
    for args, kind in [(['inspect', '--format', '{{json .State}} restartCount={{.RestartCount}}', cid], 'state'),
                       (['logs', '--tail', '100', '--timestamps', cid], 'logs')]:
        try:
            result = subprocess.run(['docker', *args], capture_output=True, timeout=15)
            diagnostic(f'{label}: {kind}; exit={result.returncode}',
                       result.stdout + b'\n' + result.stderr)
        except Exception as exc:
            diagnostic(f'{label}: cannot collect {kind}', type(exc).__name__)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    with tmp.open('w', encoding='utf-8', newline='\n') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')
    tmp.chmod(0o600)
    tmp.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def domain(value):
    value = value.strip().lower()
    if len(value) > 253 or '.' not in value or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
        for p in value.split('.')
    ):
        raise ValueError('Нужен DNS-домен без схемы, порта и пути; IDN вводите в punycode.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Введите домен, а не IP-адрес.')


def ask_domain(prompt):
    while True:
        try:
            return domain(input(prompt + ': '))
        except ValueError as e:
            print(e)


def validate(s):
    if s.get('schema') != 1:
        raise ValueError('Неподдерживаемая версия state.json.')
    selected = s.get('selected', [])
    extras = s.get('extras_requested', [])
    if (not selected and not extras) or len(selected) != len(set(selected)) or set(selected) - IMAGES.keys():
        raise ValueError('Некорректный список компонентов.')
    if len(extras) != len(set(extras)) or set(extras) - {'naive', 'xhttp'}:
        raise ValueError('Некорректный список дополнительных компонентов.')
    planned = s.get('extra_domains', {})
    if set(planned) != set(extras):
        raise ValueError('Для выбранных дополнений нужны домены.')
    owned = [s['fallback_domain']]
    for key in ('mtg_domain', 'panel_domain', 'hy_domain', 'reality_address'):
        if s.get(key):
            owned.append(s[key])
    owned.extend(planned.values())
    for name in owned:
        if domain(name) != name:
            raise ValueError('Домен в состоянии должен быть нормализован.')
    routes = [s['fallback_domain']]
    if 'mtg' in selected:
        domain(s['mtg_sni'])
        routes.append(s['mtg_sni'])
        expected = 'ee' + s['mtg_secret'][2:34] + s['mtg_sni'].encode().hex()
        if not re.fullmatch(r'ee[0-9a-f]+', s['mtg_secret']) or s['mtg_secret'] != expected:
            raise ValueError('Секрет mtg не соответствует SNI.')
    if 'xui' in selected:
        domain(s['reality_sni'])
        routes += [s['panel_domain'], s['reality_sni']]
        if not re.fullmatch(r'[A-Za-z0-9_-]{12,80}', s['panel_user']):
            raise ValueError('Некорректный логин панели.')
        if not re.fullmatch(r'/[A-Za-z0-9_-]{16,80}/', s['panel_path']):
            raise ValueError('Некорректный путь панели.')
        uuid.UUID(s['uuid'])
        if not re.fullmatch(r'[0-9a-f]{16}', s['short_id']):
            raise ValueError('Некорректный short ID.')
        if len(s['panel_password']) < 20:
            raise ValueError('Слишком короткий пароль панели.')
    if len(routes) != len(set(routes)):
        raise ValueError('SNI mtg, Reality, панели и fallback должны различаться.')
    if len(owned) != len(set(owned)):
        raise ValueError('Используйте отдельные домены подключения, панели, Hysteria и fallback.')
    if set(planned.values()) & {s.get('mtg_sni'), s.get('reality_sni')}:
        raise ValueError('Домены дополнений не должны совпадать с внешними SNI.')
    if 'hysteria' in selected:
        if len(s['hy_password']) < 16 or any(ord(c) < 32 for c in s['hy_password']):
            raise ValueError('Пароль Hysteria: от 16 символов, без управляющих символов.')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', s['email']):
        raise ValueError('Некорректный email.')
    if not s['public_ips']:
        raise ValueError('Нужен хотя бы один публичный IP.')
    for ip in s['public_ips']:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError('Ожидается публичный адрес VPS.')
    if not isinstance(s['ipv6'], bool):
        raise ValueError('ipv6 должен быть логическим значением.')
    if not s['ipv6'] and any(':' in ip for ip in s['public_ips']):
        raise ValueError('IPv6-адрес указан, но IPv6 отключён.')


def collect(output, cloudflare=False, extras=''):
    import cloudflare_dns as dns
    print('Выберите компоненты: 1 — mtg, 2 — 3x-ui + Reality, 3 — Hysteria 2, '
          '4 — NaiveProxy, 5 — XHTTP.')
    while True:
        choices = input('Номера через пробел [Enter — все пять]: ').split() or list('12345')
        if all(c in '12345' and len(c) == 1 for c in choices):
            break
        print('Введите только номера от 1 до 5 через пробел.')
    s = {'schema': 1, 'selected': [v for k, v in
         [('1', 'mtg'), ('2', 'xui'), ('3', 'hysteria')] if k in choices]}
    forced = set(extras.split(',')) - {''}
    if forced - {'naive', 'xhttp'}:
        raise ValueError('Неизвестное дополнение.')
    s['extras_requested'] = [v for k, v in [('4', 'naive'), ('5', 'xhttp')]
                             if k in choices or v in forced]
    while True:
        common = input('Общий домен (example.com; Enter — отдельные домены сервисов): ').strip()
        try:
            common = domain(common) if common else ''
            break
        except ValueError as exc:
            print(exc)
    if common:
        prefix = input('Метка VPS (vps1; Enter — без метки): ').strip().lower()
        s['dns_template'] = dns.validate_template({'zone': common, 'prefix': prefix})
    if cloudflare:
        zone = input(f'Зона Cloudflare [{common or "введите имя зоны"}]: ').strip() or common
        s['cloudflare_zone'] = domain(zone)
    s['public_ips'] = input('Публичные IP этого VPS (IPv4/IPv6 через пробел): ').split()
    s['public_ips'] = list(dict.fromkeys(str(ipaddress.ip_address(ip)) for ip in s['public_ips']))
    s['ipv6'] = any(':' in ip for ip in s['public_ips'])

    def own_domain(key, prompt):
        return dns.hostname(s['dns_template'], key) if common else ask_domain(prompt)

    s['fallback_domain'] = own_domain('fallback_domain', 'Ваш домен fallback-сайта')
    s['email'] = input('Email для Let’s Encrypt: ').strip()
    if 'mtg' in s['selected']:
        s['mtg_domain'] = own_domain('mtg_domain', 'Ваш домен подключения Telegram (указывает на VPS)')
        s['mtg_sni'] = ask_domain('Домен маскировки mtg (реальный HTTPS-сайт)')
        s['mtg_secret'] = 'ee' + secrets.token_hex(16) + s['mtg_sni'].encode().hex()
    if 'xui' in s['selected']:
        s['panel_domain'] = own_domain('panel_domain', 'Ваш домен панели 3x-ui')
        s['reality_address'] = own_domain('reality_address', 'Ваш домен подключения VLESS (указывает на VPS)')
        s['reality_sni'] = ask_domain('Внешний домен маскировки Reality (TLS 1.3, HTTP/2)')
        s['panel_user'] = 'u_' + secrets.token_hex(8)
        s['panel_password'] = secrets.token_urlsafe(30)
        s['panel_path'] = '/' + secrets.token_urlsafe(24) + '/'
        s['uuid'] = str(uuid.uuid4())
        s['short_id'] = secrets.token_hex(8)
    if 'hysteria' in s['selected']:
        s['hy_domain'] = own_domain('hy_domain', 'Ваш домен Hysteria 2')
        pw = getpass.getpass('Пароль Hysteria (от 16 символов; Enter — сгенерировать): ')
        if pw and pw != getpass.getpass('Повторите пароль: '):
            raise ValueError('Пароли не совпали.')
        s['hy_password'] = pw or secrets.token_urlsafe(30)
    s['extra_domains'] = {name: own_domain(name, f'Ваш отдельный домен {name}')
                          for name in s['extras_requested']}
    validate(s)
    names = owned_domains(s)
    if cloudflare and any(not name.endswith('.' + s['cloudflare_zone']) for name in names):
        raise ValueError('Для --cloudflare все имена должны быть поддоменами указанной зоны.')
    print('\nДомены подключения (A/AAAA на указанные IP VPS, без CDN):')
    for name in names:
        print('  ' + name)
    if not cloudflare:
        input('Настройте эти DNS-записи у своего провайдера и нажмите Enter для проверки: ')
    write_json(output, s)


def owned_domains(s):
    return sorted({s[k] for k in ('fallback_domain', 'mtg_domain', 'panel_domain',
                                  'hy_domain', 'reality_address') if k in s}
                  | set(s.get('extra_domains', {}).values()))


def check_plan(s, extra_path):
    installed = read_json(extra_path).get('services', {}) if Path(extra_path).exists() else {}
    missing = sorted(set(s.get('extras_requested', [])) - set(installed))
    if missing:
        raise RuntimeError('Не установлены выбранные дополнения: ' + ', '.join(missing) +
                           '. Для продолжения выполните sudo bash deploy-proxy.sh --add=' + ','.join(missing))


def resolve(name):
    return {str(ipaddress.ip_address(v[4][0])) for v in
            socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}


def preflight(s):
    validate(s)
    socket.setdefaulttimeout(10)
    expected = {str(ipaddress.ip_address(ip)) for ip in s['public_ips']}
    domains = owned_domains(s)
    for name in sorted(domains):
        found = resolve(name)
        if not found or not found <= expected:
            raise ValueError(f'DNS {name}: {sorted(found)}; ожидаются только IP VPS {sorted(expected)}. '
                             'Проверьте A/AAAA и отключите CDN-проксирование.')
        print(f'[OK] DNS {name}: {", ".join(sorted(found))}')
    for key in ('mtg_sni', 'reality_sni'):
        if key not in s:
            continue
        name = s[key]
        addresses = resolve(name)
        if addresses & expected or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError(f'{key}: цель должна быть внешним публичным HTTPS-сайтом, без петли на VPS.')
        ctx = ssl.create_default_context()
        if key == 'reality_sni':
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols(['h2'])
        with socket.create_connection((name, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=name) as tls:
                if key == 'reality_sni' and tls.selected_alpn_protocol() != 'h2':
                    raise ValueError('Цель Reality должна поддерживать HTTP/2.')
        print(f'[OK] HTTPS-цель {name}')
    if s['ipv6']:
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(('::1', 0))


def cert_domains(s):
    return sorted({s[k] for k in ('fallback_domain', 'panel_domain', 'hy_domain') if k in s})


def generate(s, images, target):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    services = {}
    logging = {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}
    for name in s['selected']:
        image = images[name]
        if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', image):
            raise ValueError(f'Образ {name} не закреплён digest.')
        services[name] = {'image': image, 'restart': 'unless-stopped', 'logging': logging,
                          'security_opt': ['no-new-privileges:true']}
    if 'mtg' in services:
        (target / 'mtg.toml').write_text(
            f'secret = "{s["mtg_secret"]}"\nbind-to = "0.0.0.0:3128"\n', encoding='utf-8')
        services['mtg'].update({'ports': ['127.0.0.1:8443:3128'],
                               'volumes': [f'{ROOT}/mtg.toml:/config.toml:ro']})
    if 'xui' in services:
        services['xui'].update({'ports': ['127.0.0.1:2053:2053', '127.0.0.1:10443:10443'],
            'environment': {'XUI_ENABLE_FAIL2BAN': 'false', 'TZ': 'UTC'},
            'volumes': [f'{ROOT}/xui-db:/etc/x-ui']})
    if 'hysteria' in services:
        services['hysteria'].update({'network_mode': 'host',
            'volumes': [f'{ROOT}/hysteria.json:/etc/hysteria/config.json:ro',
                        '/etc/letsencrypt:/etc/letsencrypt:ro'],
            'command': ['server', '-c', '/etc/hysteria/config.json']})
        cert = f'/etc/letsencrypt/live/{s["hy_domain"]}'
        write_json(target / 'hysteria.json', {
            'listen': ':443' if s['ipv6'] else '0.0.0.0:443',
            'tls': {'cert': cert + '/fullchain.pem', 'key': cert + '/privkey.pem'},
            'auth': {'type': 'password', 'password': s['hy_password']},
            'masquerade': {'type': 'proxy', 'proxy': {
                'url': 'https://www.microsoft.com/', 'rewriteHost': True}}})
    # Compose hashes service labels, but does not hash files in bind mounts.
    # A changed config must recreate its container so it reopens the new inode.
    for name, filename in (('mtg', 'mtg.toml'), ('hysteria', 'hysteria.json')):
        if name in services:
            services[name]['labels'] = {'io.proxy-deploy.config-sha256':
                hashlib.sha256((target / filename).read_bytes()).hexdigest()}
    write_json(target / 'compose.json', {'name': 'proxy-deploy', 'services': services})


def nginx_http(s, final):
    v6 = '    listen [::]:80;\n' if s['ipv6'] else ''
    out = f'''# Managed by deploy-proxy.sh
server {{
    listen 80;
{v6}    server_name {' '.join(cert_domains(s))};
    location ^~ /.well-known/acme-challenge/ {{ root /var/www/proxy-acme; }}
    location / {{ return 404; }}
}}
'''
    if not final:
        return out
    for name, port, panel in [(s['fallback_domain'], 9443, False)] + (
            [(s['panel_domain'], 9444, True)] if 'xui' in s['selected'] else []):
        out += f'''server {{
    listen 127.0.0.1:{port} ssl;
    server_name {name};
    ssl_certificate /etc/letsencrypt/live/{name}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{name}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
'''
        if panel:
            out += f'''    access_log off;
    location {s['panel_path']} {{
        proxy_pass http://127.0.0.1:2053;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $proxy_deploy_connection;
        proxy_read_timeout 300s;
    }}
    location / {{ return 404; }}
'''
        else:
            out += '    root /var/www/proxy-fallback;\n    index index.html;\n'
        out += '}\n'
    if 'xui' in s['selected']:
        out = 'map $http_upgrade $proxy_deploy_connection { default upgrade; "" close; }\n' + out
    return out


def nginx_stream(s):
    entries = ['        default 127.0.0.1:9443;']
    if 'mtg' in s['selected']:
        entries.append(f'        {s["mtg_sni"]} 127.0.0.1:8443;')
    if 'xui' in s['selected']:
        entries += [f'        {s["panel_domain"]} 127.0.0.1:9444;',
                    f'        {s["reality_sni"]} 127.0.0.1:10443;']
    v6 = '        listen [::]:443;\n' if s['ipv6'] else ''
    return '''# Managed by deploy-proxy.sh
stream {
    map $ssl_preread_server_name $proxy_deploy_backend {
''' + '\n'.join(entries) + '''
    }
    server {
        listen 443;
''' + v6 + '''        ssl_preread on;
        proxy_pass $proxy_deploy_backend;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
    }
}
'''


def docker_output(args, timeout=60):
    # Never echo arguments: CLI operations may contain passwords.
    try:
        result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        diagnostic('Docker timeout', (exc.stdout or b'') if not exc.stderr else exc.stderr)
        raise RuntimeError('Истекло время ожидания Docker (аргументы скрыты).') from None
    if result.returncode:
        diagnostic(f'Docker failed; exit={result.returncode}', result.stdout + '\n' + result.stderr)
        raise RuntimeError(f'Команда Docker завершилась с кодом {result.returncode}; детали в журнале.')
    return result.stdout


def database_idle(target):
    """Fail closed if Docker is unavailable or a running container mounts this DB directory."""
    ids = docker_output(['ps', '-q']).split()
    if not ids:
        return
    containers = json.loads(docker_output(['inspect', *ids]))
    directory = Path(target).parent.resolve()
    for container in containers:
        for mount in container.get('Mounts', []):
            source = mount.get('Source')
            if not source:
                continue
            source = Path(source).resolve()
            if source == directory or source in directory.parents or directory in source.parents:
                raise RuntimeError('Восстановление базы запрещено: работающий контейнер использует каталог базы.')


def restore_database(backup, target):
    """Prepare + validate a standalone DB, prove no Docker readers/writers, preserve displaced files."""
    backup, target = Path(backup), Path(target)
    if not backup.is_file():
        raise RuntimeError('Нет резервной копии базы; восстановление отменено.')
    database_idle(target)
    fd, temp = tempfile.mkstemp(prefix='.restore-', suffix='.db', dir=target.parent)
    os.close(fd)
    temp = Path(temp)
    moved = []
    recovery = None
    try:
        shutil.copyfile(backup, temp)
        temp.chmod(0o600)
        with closing(sqlite3.connect(temp.as_uri() + '?mode=ro&immutable=1', uri=True)) as db:
            if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise RuntimeError('Резервная база не прошла SQLite quick_check.')
        with temp.open('r+b') as f:
            os.fsync(f.fileno())
        # Recheck immediately before replacement. Concurrent administration is unsupported.
        database_idle(target)
        recovery = Path(tempfile.mkdtemp(prefix='before-restore-', dir=backup.parent))
        recovery.chmod(0o700)
        for original in (target, Path(str(target) + '-wal'), Path(str(target) + '-shm')):
            if original.exists():
                saved = recovery / original.name
                original.replace(saved)
                moved.append((original, saved))
        temp.replace(target)
        diagnostic('Database restored', f'Previous files preserved in {recovery}')
    except Exception:
        # If replacement fails, put back the original DB plus its matching WAL/SHM.
        for original, saved in reversed(moved):
            saved.replace(original)
        raise
    finally:
        temp.unlink(missing_ok=True)


class Panel:
    def __init__(self, s, token):
        SECRETS.add(token)
        self.base = 'http://127.0.0.1:2053' + s['panel_path'] + 'panel/api/'
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, path, data=None):
        body = None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(self.base + path, data=body, headers={
            'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=20) as res:
                result = json.load(res)
        except urllib.error.HTTPError as exc:
            diagnostic(f'3x-ui {path}; HTTP {exc.code}', exc.read(65536))
            raise RuntimeError(f'API 3x-ui: {path}, HTTP {exc.code}; детали в журнале.') from None
        except Exception as exc:
            diagnostic(f'3x-ui {path}: request failed', f'{type(exc).__name__}: {exc}')
            raise RuntimeError(f'API 3x-ui: запрос {path} не выполнен; детали в журнале.') from None
        if result.get('success') is not True:
            diagnostic(f'3x-ui {path}: success=false', json.dumps(result, ensure_ascii=False))
            raise RuntimeError(f'API 3x-ui отклонил запрос {path}.')
        return result.get('obj')


def panel_api(s, cid, state_path):
    settings = docker_output(['exec', cid, '/app/x-ui', 'setting', '-show'])
    if re.search(r'hasDefaultCredential:\s*true', settings):
        raise RuntimeError('В панели остался пароль admin/admin; публикация запрещена.')
    if not re.search(r'hasDefaultCredential:\s*false', settings):
        raise RuntimeError('Не удалось проверить отсутствие стандартных учётных данных панели.')
    if not re.search(r'^port:\s*2053\s*$', settings, re.M) or not re.search(
            r'^webBasePath:\s*' + re.escape(s['panel_path']) + r'\s*$', settings, re.M):
        raise RuntimeError('Порт/путь панели изменён вручную и не совпадает с state.json.')
    # Named CLI token is rotated in place, never accumulated. Saved outside logs.
    output = docker_output(['exec', cid, '/app/x-ui', 'setting',
                            '-getApiToken', '-tokenName', 'proxy-deploy'])
    match = re.search(r'^apiToken:\s*(\S+)\s*$', output, re.M)
    if not match:
        raise RuntimeError('3x-ui не выдал API-токен ожидаемого формата.')
    api = Panel(s, match.group(1))
    inbounds = api.call('inbounds/list') or []
    matches = [i for i in inbounds if i.get('remark') == 'proxy-deploy-reality']
    if len(matches) > 1:
        raise RuntimeError('Найдено несколько управляемых Reality inbound.')
    if matches:
        old = matches[0]
        stream = json.loads(old['streamSettings'])
        clients = json.loads(old['settings'])['clients']
        reality = stream['realitySettings']
        if (old['port'] != 10443 or not old['enable'] or old['protocol'] != 'vless'
                or old.get('listen') not in ('', '0.0.0.0')
                or stream.get('security') != 'reality'
                or stream.get('network') not in ('tcp', 'raw')
                or s['reality_sni'] not in reality['serverNames']
                or reality.get('target', reality.get('dest')) != s['reality_sni'] + ':443'
                or reality.get('privateKey') != s.get('reality_private')
                or s['short_id'] not in reality.get('shortIds', [])
                or not any(c['id'] == s['uuid'] and c.get('enable', True)
                           and c.get('flow') == 'xtls-rprx-vision' for c in clients)):
            raise RuntimeError('Reality изменён вручную. Настройки сохранены; автоматическая перезапись запрещена.')
        return api
    if any(i['port'] == 10443 for i in inbounds):
        raise RuntimeError('Порт 10443 уже занят другим inbound в панели.')
    if not s.get('reality_private'):
        keys = api.call('server/getNewX25519Cert')
        for key in ('privateKey', 'publicKey'):
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', keys[key]):
                raise RuntimeError('Неподдерживаемый формат ключа X25519.')
        s['reality_private'], s['reality_public'] = keys['privateKey'], keys['publicKey']
        register_secrets(s)
        write_json(state_path, s)
    client = {'id': s['uuid'], 'flow': 'xtls-rprx-vision', 'email': 'proxy-deploy-client',
              'enable': True, 'limitIp': 0, 'totalGB': 0, 'expiryTime': 0,
              'subId': secrets.token_hex(8), 'reset': 0}
    stream = {'network': 'tcp', 'security': 'reality', 'realitySettings': {
        'show': False, 'target': s['reality_sni'] + ':443', 'xver': 0,
        'serverNames': [s['reality_sni']], 'privateKey': s['reality_private'],
        'shortIds': [s['short_id']], 'settings': {
            'publicKey': s['reality_public'], 'fingerprint': 'chrome',
            'serverName': s['reality_sni'], 'spiderX': '/'}}}
    api.call('inbounds/add', {'remark': 'proxy-deploy-reality', 'enable': True,
        'listen': '0.0.0.0', 'port': 10443, 'protocol': 'vless', 'expiryTime': 0,
        'total': 0, 'up': 0, 'down': 0,
        'settings': json.dumps({'clients': [client], 'decryption': 'none', 'fallbacks': []}),
        'streamSettings': json.dumps(stream),
        'sniffing': json.dumps({'enabled': False})})
    api.call('server/restartXrayService', {})
    return api


def client_probe(s, images, service, target):
    """Authenticate a real client through localhost:443, then fetch HTTPS through it."""
    target = Path(target)
    register_secrets(s)
    port = 18081 if service == 'xui' else 18082
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))  # Fail before starting a probe if occupied.
    if service == 'xui':
        data = {'log': {'loglevel': 'error'},
            'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                'address': '127.0.0.1', 'port': 443, 'users': [{
                    'id': s['uuid'], 'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'reality',
                    'realitySettings': {'serverName': s['reality_sni'], 'fingerprint': 'chrome',
                        'publicKey': s['reality_public'], 'shortId': s['short_id'], 'spiderX': '/'}}}]}
        entry = ['--entrypoint', '/bin/sh']
        command = ['-c', 'for f in /app/bin/xray /app/bin/xray-linux-*; do '
                   'if [ -f "$f" ] && [ -x "$f" ]; then exec "$f" run -c /probe.json; fi; '
                   'done; exit 127']
    else:
        data = {'server': '127.0.0.1:443', 'auth': s['hy_password'],
                'tls': {'sni': s['hy_domain'], 'insecure': False},
                'socks5': {'listen': f'127.0.0.1:{port}'}}
        entry = []
        command = ['client', '-c', '/probe.json']
    write_json(target, data)
    cid = None
    try:
        cid = docker_output(['run', '-d', '--network', 'host',
            '--label', 'proxy-deploy.probe=true', '--security-opt', 'no-new-privileges:true',
            '-v', f'{target}:/probe.json:ro', *entry, images[service], *command]).strip()
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise RuntimeError('Не получен идентификатор проверочного контейнера.')
        for _ in range(30):
            try:
                tcp_probe(port)
                break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError('Проверочный клиент не запустился за 30 секунд.')
        result = subprocess.run(['curl', '--fail', '--silent', '--show-error',
            '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
            '--connect-timeout', '10', '--max-time', '30',
            'https://www.microsoft.com/', '--output', os.devnull],
            capture_output=True, timeout=40)
        if result.returncode:
            diagnostic(f'{service}: client curl exit={result.returncode}', result.stderr)
            raise RuntimeError('HTTPS-запрос через проверочный клиент не выполнен. '
                               'Проверьте настройки и исходящий доступ к www.microsoft.com.')
    except Exception as exc:
        diagnostic(f'{service}: client probe failed', type(exc).__name__)
        if cid:
            capture_container(cid, f'{service}: probe before removal')
        raise
    finally:
        if cid and re.fullmatch(r'[0-9a-f]{64}', cid):
            # Cleanup errors are fatal too; never leave an unnoticed local SOCKS proxy.
            docker_output(['rm', '-f', cid])
        target.unlink(missing_ok=True)


def mtg_probe(s, cid):
    data = json.loads(docker_output(['exec', cid, '/mtg', 'access', '/config.toml']))
    if data.get('secret', {}).get('hex') != s['mtg_secret']:
        raise RuntimeError('Работающий mtg использует другой секрет.')
    # Public links are built from the explicit server domain and public port,
    # never from the container's private address or bind-to port.
    tcp_probe(8443)


def init_panel(s, image, state_path):
    db = ROOT / 'xui-db' / 'x-ui.db'
    if db.exists():
        return  # Never reset an existing panel password or path.
    docker_output(['run', '--rm', '--network', 'none', '--entrypoint', '/app/x-ui',
        '-v', f'{ROOT}/xui-db:/etc/x-ui', image, 'setting', '-port', '2053',
        '-username', s['panel_user'], '-password', s['panel_password'],
        '-webBasePath', s['panel_path'], '-listenIP', '0.0.0.0'])
    if not db.exists():
        raise RuntimeError('CLI 3x-ui не создал базу данных.')


def credentials(s, output, extra=None):
    lines = ['Секретные данные. Файл доступен только root.', '']
    if 'mtg' in s['selected']:
        query = urllib.parse.urlencode({'server': s['mtg_domain'], 'port': 443, 'secret': s['mtg_secret']})
        lines += ['Telegram: tg://proxy?' + query, '']
    if 'xui' in s['selected']:
        lines += ['Панель: https://' + s['panel_domain'] + s['panel_path'],
                  'Логин: ' + s['panel_user'], 'Первоначальный пароль: ' + s['panel_password']]
        if s.get('reality_public'):
            query = urllib.parse.urlencode({'encryption': 'none', 'security': 'reality',
                'sni': s['reality_sni'], 'fp': 'chrome', 'pbk': s['reality_public'],
                'sid': s['short_id'], 'type': 'tcp', 'flow': 'xtls-rprx-vision', 'spx': '/'})
            lines += [f'VLESS: vless://{s["uuid"]}@{s["reality_address"]}:443?{query}#Reality', '']
    if 'hysteria' in s['selected']:
        lines += ['Hysteria: hysteria2://' + urllib.parse.quote(s['hy_password'], safe='') +
                  '@' + s['hy_domain'] + ':443/?sni=' + s['hy_domain'] + '#Hysteria2', '']
    for name, item in (extra or {}).get('services', {}).items():
        if name == 'naive':
            uri = f'https://{item["user"]}:{item["password"]}@{item["domain"]}:443'
            lines += ['NaiveProxy: ' + uri, 'Режим HTTPS / HTTP/2; не QUIC.', '']
        elif name == 'xhttp':
            query = urllib.parse.urlencode({'encryption': 'none', 'security': 'tls',
                'sni': item['domain'], 'alpn': 'h2', 'fp': 'chrome', 'type': 'xhttp',
                'path': item['path'], 'mode': 'packet-up'})
            lines += [f'XHTTP: vless://{item["uuid"]}@{item["domain"]}:443?{query}#XHTTP', '']
    path = Path(output)
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                     dir=path.parent, prefix='.credentials-', delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write('\n'.join(lines) + '\n')
        except BaseException:
            f.close()
            tmp.unlink(missing_ok=True)
            raise
    try:
        tmp.chmod(0o600)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def tls_probe(name, path='/', ipv6=False):
    ctx = ssl.create_default_context()
    with socket.create_connection(('::1' if ipv6 else '127.0.0.1', 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as tls:
            tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n'.encode())
            first = tls.recv(4096).split(b'\r\n', 1)[0]
            if not re.match(rb'HTTP/1\.[01] (200|301|302|303|307|308)\b', first):
                raise RuntimeError('Неожиданный HTTP-ответ через Nginx.')


def tcp_probe(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5):
        pass


def main():
    global DIAGNOSTIC_PATH
    DIAGNOSTIC_PATH = os.environ.get('PROXY_DEPLOY_LOG')
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['collect', 'preflight', 'generate', 'nginx', 'domains',
        'init-panel', 'panel', 'credentials', 'tls', 'tcp', 'image', 'client-probe', 'mtg-probe',
        'restore-db', 'capture', 'check-plan'])
    parser.add_argument('--state', default=str(ROOT / 'state.json'))
    parser.add_argument('--output')
    parser.add_argument('--images', default=str(ROOT / 'images.json'))
    parser.add_argument('--final', action='store_true')
    parser.add_argument('--cid')
    parser.add_argument('--name')
    parser.add_argument('--input')
    parser.add_argument('--cloudflare', action='store_true')
    parser.add_argument('--extras', default='')
    args = parser.parse_args()
    if args.action == 'collect':
        collect(args.output, args.cloudflare, args.extras)
        return
    if args.action == 'image':
        print(IMAGES[args.name])
        return
    if args.action == 'tcp':
        tcp_probe(int(args.name))
        return
    s = read_json(args.state)
    register_secrets(s)
    validate(s)
    if args.action == 'check-plan':
        check_plan(s, ROOT / 'extras' / 'state.json')
    elif args.action == 'preflight':
        preflight(s)
    elif args.action == 'domains':
        print('\n'.join(cert_domains(s)))
    elif args.action == 'generate':
        generate(s, read_json(args.images), args.output)
    elif args.action == 'nginx':
        p = Path(args.output)
        (p / 'conf.d' / 'proxy-deploy-http.conf').write_text(nginx_http(s, args.final), encoding='utf-8')
        (p / 'proxy-deploy-stream.conf').write_text(nginx_stream(s) if args.final else '', encoding='utf-8')
        main_conf = p / 'nginx.conf'
        original = main_conf.read_text(encoding='utf-8')
        include = 'include /etc/nginx/proxy-deploy-stream.conf;'
        if include not in original:
            main_conf.write_text(original + '\n' + include + '\n', encoding='utf-8')
    elif args.action == 'init-panel':
        init_panel(s, read_json(args.images)['xui'], args.state)
    elif args.action == 'panel':
        panel_api(s, args.cid, args.state)
    elif args.action == 'credentials':
        extra_path = ROOT / 'extras' / 'state.json'
        if (ROOT / 'extras' / 'pending.json').exists():
            raise RuntimeError('Есть незавершённое добавление; сначала повторите --add для восстановления.')
        extra = None
        if extra_path.exists():
            if extra_path.is_symlink() or extra_path.stat().st_uid != 0 or extra_path.stat().st_mode & 0o077:
                raise RuntimeError('Состояние дополнений должно принадлежать root с правами 600.')
            extra = read_json(extra_path)
            from proxy_extras import validate as validate_extras
            validate_extras(extra, s)
        credentials(s, args.output, extra)
        (ROOT / 'extras' / 'credentials.txt').unlink(missing_ok=True)
    elif args.action == 'client-probe':
        client_probe(s, read_json(args.images), args.name, args.output)
    elif args.action == 'mtg-probe':
        mtg_probe(s, args.cid)
    elif args.action == 'restore-db':
        restore_database(args.input, ROOT / 'xui-db' / 'x-ui.db')
    elif args.action == 'capture':
        capture_container(args.cid, args.name or 'container')
    elif args.action == 'tls':
        name = s['panel_domain'] if args.name == 'panel' else s['fallback_domain']
        path = s['panel_path'] if args.name == 'panel' else '/'
        tls_probe(name, path)
        if s['ipv6']:
            tls_probe(name, path, True)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        # No traceback or subprocess arguments containing credentials.
        message = f'{type(exc).__name__}: {exc}'
        diagnostic('Operation failed', message)
        print('[ОШИБКА] ' + redact(message), file=sys.stderr)
        sys.exit(1)

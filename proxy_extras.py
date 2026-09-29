#!/usr/bin/env python3
"""Additive HTTPS services. Called under deploy-proxy.sh's exclusive flock.

Never owns the legacy Compose project, its DB, firewall or package installation.
Only new services are started/removed; existing service definitions are immutable.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

import proxy_config as base

ROOT = base.ROOT / 'extras'
STREAM = Path('/etc/nginx/proxy-deploy-stream.conf')
MAP = Path('/etc/nginx/proxy-deploy-extras.map')
HOOK = Path('/etc/letsencrypt/renewal-hooks/deploy/proxy-deploy-extras')
PROJECT = 'proxy-deploy-extras'
PORTS = {'naive': 11443, 'xhttp': 12443}
NAIVE_VERSION = 'v154.0.8037.49-2'
NAIVE_HASHES = {
    'amd64': ('x64', '4823f654b1a3856efefa6980a97997b6c5153a693e4a4541a9a10e03d7e7d9e3'),
    'arm64': ('arm64', 'e2eab668815b0ee7f44db44009cdb86b863235ef92564d31e39840405e3e18bb'),
}
FORWARDPROXY = 'd62c80d3dd2c706b6b87579844d2397bddd18317'
XRAY_IMAGE = 'ghcr.io/xtls/xray-core:26.3.27'


def run(args, timeout=120):
    """No shell interpolation, no command lines or credentials in diagnostics."""
    try:
        result = subprocess.run([str(a) for a in args], capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        base.diagnostic('extras: timeout', exc.stderr or '')
        raise RuntimeError(f'Истекло время ожидания {args[0]}.') from None
    if result.returncode:
        base.diagnostic(f'extras: {args[0]} exit={result.returncode}',
                        result.stdout + '\n' + result.stderr)
        raise RuntimeError(f'{args[0]}: код {result.returncode}; подробности в журнале.')
    return result.stdout.strip()


def compose(path, *args):
    return run(['docker', 'compose', '--project-name', PROJECT, '-f', path, *args])


def register(s):
    for item in s.get('services', {}).values():
        for key in ('user', 'password', 'uuid', 'path'):
            if item.get(key):
                base.SECRETS.add(item[key])
        if item.get('password'):
            import base64
            base.SECRETS.add(base64.b64encode(
                (item['user'] + ':' + item['password']).encode()).decode())


def validate(s, legacy):
    if s.get('schema') != 1 or set(s.get('services', {})) - PORTS.keys():
        raise ValueError('Некорректное состояние дополнительных сервисов.')
    used = {v for k, v in legacy.items() if k.endswith(('_domain', '_sni'))}
    used.add(legacy.get('reality_address'))
    for name, item in s['services'].items():
        domain = base.domain(item['domain'])
        if domain != item['domain'] or domain in used:
            raise ValueError('Каждому новому сервису нужен отдельный домен без совпадений SNI.')
        used.add(domain)
        if name == 'naive':
            for key in ('user', 'password'):
                if not re.fullmatch(r'[A-Za-z0-9_-]{20,80}', item[key]):
                    raise ValueError('Некорректные учётные данные NaiveProxy.')
        else:
            uuid.UUID(item['uuid'])
            if not re.fullmatch(r'/[a-f0-9]{32}/', item['path']):
                raise ValueError('Некорректный путь XHTTP.')


def collect(s, requested, legacy, dns_template=None):
    result = copy.deepcopy(s)
    if dns_template:
        result['dns_template'] = dict(dns_template)
    for name in requested:
        if name in result['services']:
            continue
        if name in legacy.get('extra_domains', {}):
            domain = legacy['extra_domains'][name]
        elif dns_template:
            from cloudflare_dns import hostname
            domain = hostname(dns_template, name)
        else:
            domain = base.ask_domain(f'Ваш отдельный домен {name} (DNS only, A/AAAA на VPS)')
        item = {'domain': domain}
        if name == 'naive':
            item.update(user=secrets.token_urlsafe(18), password=secrets.token_urlsafe(30))
        else:
            item.update(uuid=str(uuid.uuid4()), path='/' + secrets.token_hex(16) + '/')
        result['services'][name] = item
    validate(result, legacy)
    return result


def stream_with_include(text):
    directive = f'        include {MAP};'
    if directive in text:
        return text
    marker = '    map $ssl_preread_server_name $proxy_deploy_backend {\n'
    if text.count(marker) != 1:
        raise RuntimeError('Не найдена управляемая SNI-таблица; Nginx не изменён.')
    return text.replace(marker, marker + directive + '\n', 1)


def routes(s):
    return ''.join(f'{item["domain"]} 127.0.0.1:{PORTS[name]};\n'
                   for name, item in sorted(s['services'].items()))


def pull(tag):
    print(f'[+] Подготовка образа {tag}', flush=True)
    run(['docker', 'pull', tag], 600)
    digest = run(['docker', 'image', 'inspect', tag, '--format', '{{index .RepoDigests 0}}'])
    if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}', digest):
        raise RuntimeError('Не удалось закрепить Docker-образ по digest.')
    return digest


def build_naive(work):
    arch = run(['dpkg', '--print-architecture'])
    if arch not in NAIVE_HASHES:
        raise RuntimeError('NaiveProxy: поддерживаются amd64 и arm64.')
    asset_arch, checksum = NAIVE_HASHES[arch]
    filename = f'naiveproxy-{NAIVE_VERSION}-linux-{asset_arch}.tar.xz'
    archive = work / filename
    run(['curl', '--fail', '--silent', '--show-error', '--location', '--retry', '3',
         '--connect-timeout', '15', '--max-time', '300',
         f'https://github.com/klzgrad/naiveproxy/releases/download/{NAIVE_VERSION}/{filename}',
         '-o', archive], 1000)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
        raise RuntimeError('Контрольная сумма официального клиента NaiveProxy не совпала.')
    # Extract only the named regular executable; never extract arbitrary archive paths.
    with tarfile.open(archive) as tar:
        member = tar.getmember(filename[:-7] + '/naive')
        if not member.isfile():
            raise RuntimeError('Некорректный архив NaiveProxy.')
        with tar.extractfile(member) as source, (work / 'naive').open('wb') as dest:
            shutil.copyfileobj(source, dest)
    (work / 'naive').chmod(0o755)
    builder = pull('caddy:2.11.4-builder')
    runtime = pull('debian:bookworm-slim')
    (work / 'Dockerfile').write_text(f'''FROM {builder} AS builder
RUN GOMAXPROCS=2 GOFLAGS=-p=2 xcaddy build v2.11.4 --with github.com/caddyserver/forwardproxy=github.com/klzgrad/forwardproxy@{FORWARDPROXY}
FROM {runtime}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libnss3 libnspr4 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY naive /usr/bin/naive
ENTRYPOINT ["/usr/bin/caddy"]
''', encoding='utf-8')
    print('[+] Сборка Caddy с NaiveProxy; первый запуск может занять несколько минут.', flush=True)
    run(['docker', 'build', '--iidfile', work / 'image.id', work], 1800)
    image = (work / 'image.id').read_text().strip()
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise RuntimeError('Некорректный ID сборки NaiveProxy.')
    return image


def caddy_config(item):
    cert = '/etc/letsencrypt/live/' + item['domain']
    return f'''{{
    auto_https off
    admin localhost:2019
    order forward_proxy before respond
    servers {{
        protocols h1 h2
    }}
    log {{
        exclude http.log.error
    }}
}}
:443, {item['domain']} {{
    tls {cert}/fullchain.pem {cert}/privkey.pem
    forward_proxy {{
        basic_auth {item['user']} {item['password']}
        hide_ip
        hide_via
        probe_resistance
    }}
    respond "Welcome" 200
}}
'''


def xray_config(item):
    cert = '/etc/letsencrypt/live/' + item['domain']
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{
        'listen': '0.0.0.0', 'port': 443, 'protocol': 'vless',
        'settings': {'clients': [{'id': item['uuid']}], 'decryption': 'none'},
        'streamSettings': {'network': 'xhttp', 'security': 'tls',
            'tlsSettings': {'alpn': ['h2', 'http/1.1'], 'certificates': [{
                'certificateFile': cert + '/fullchain.pem', 'keyFile': cert + '/privkey.pem'}]},
            'xhttpSettings': {'path': item['path'], 'mode': 'packet-up'}}}],
        'outbounds': [{'protocol': 'freedom'}]}


def service_definition(name, item, image, directory):
    filename = 'Caddyfile' if name == 'naive' else 'xhttp.json'
    return {'image': image, 'pull_policy': 'never', 'user': '0:0', 'restart': 'unless-stopped',
        'security_opt': ['no-new-privileges:true'],
        'ports': [f'127.0.0.1:{PORTS[name]}:443'],
        'volumes': [f'{directory / filename}:/config/{filename}:ro',
                    '/etc/letsencrypt:/etc/letsencrypt:ro'],
        'command': (['run', '--config', '/config/Caddyfile', '--adapter', 'caddyfile']
                    if name == 'naive' else ['run', '-c', '/config/xhttp.json']),
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}


def core_snapshot():
    """Read-only evidence that the protected services were not recreated/restarted."""
    files = {}
    for name in ('state.json', 'compose.json', 'images.json', 'mtg.toml', 'hysteria.json'):
        path = base.ROOT / name
        if path.exists():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    ids = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=proxy-deploy']).split()
    containers = {}
    if ids:
        for c in json.loads(run(['docker', 'inspect', *ids])):
            name = c['Config']['Labels'].get('com.docker.compose.service')
            containers[name] = (c['Id'], c['State']['StartedAt'], c['RestartCount'], c['State']['Status'])
    return {'files': files, 'containers': containers}


def write_text(path, text, mode=0o600):
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text, encoding='utf-8', newline='\n')
    tmp.chmod(mode)
    tmp.replace(path)


def snapshot_files(paths):
    return {str(p): p.read_text(encoding='utf-8') if p.exists() else None for p in paths}


def restore_files(saved):
    for filename, content in saved.items():
        path = Path(filename)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            write_text(path, content, 0o700 if path == HOOK else 0o600)


def renew_hook(s):
    # Independent of the old hook. Neither mtg nor Hysteria is restarted.
    lines = ['#!/usr/bin/env bash', 'set -Eeuo pipefail',
             'case "${RENEWED_LINEAGE:-}" in']
    for name, item in s['services'].items():
        lines.append(f'  /etc/letsencrypt/live/{item["domain"]})')
        lines.extend(['    exec 9>/run/lock/proxy-deploy.lock', '    flock -w 120 9'])
        prefix = f'    docker compose --project-name {PROJECT} -f {ROOT}/compose.json'
        if name == 'naive':
            lines.append(prefix + ' exec -T naive caddy reload --force --config /config/Caddyfile --adapter caddyfile')
        else:
            lines.append(prefix + ' restart --no-deps xhttp')
        lines.append('    ;;')
    lines += ['esac', '']
    return '\n'.join(lines)


def export_profiles(s):
    for name, item in s['services'].items():
        if name == 'naive':
            uri = f'https://{item["user"]}:{item["password"]}@{item["domain"]}:443'
            base.write_json(ROOT / 'naive-client.json', {
                'listen': 'socks://127.0.0.1:1080', 'proxy': uri})
    legacy = base.read_json(base.ROOT / 'state.json')
    base.validate(legacy)
    validate(s, legacy)
    base.credentials(legacy, base.ROOT / 'credentials.txt', s)
    (ROOT / 'credentials.txt').unlink(missing_ok=True)


def probe(name, item, definition, directory):
    port = 18083 if name == 'naive' else 18084
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', port))
    if name == 'naive':
        data = {'listen': f'socks://127.0.0.1:{port}',
            'proxy': f'https://{item["user"]}:{item["password"]}@{item["domain"]}:443',
            'host-resolver-rules': f'MAP {item["domain"]} 127.0.0.1'}
        entry = '/usr/bin/naive'
        command = ['/probe.json']
    else:
        data = {'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                'address': '127.0.0.1', 'port': 443,
                'users': [{'id': item['uuid'], 'encryption': 'none'}]}]},
                'streamSettings': {'network': 'xhttp', 'security': 'tls',
                    'tlsSettings': {'serverName': item['domain'], 'alpn': ['h2'], 'fingerprint': 'chrome'},
                    'xhttpSettings': {'path': item['path'], 'mode': 'packet-up'}}}]}
        entry = '/usr/local/bin/xray'
        command = ['run', '-c', '/probe.json']
    path = directory / f'probe-{name}.json'
    base.write_json(path, data)
    cid = None
    try:
        cid = run(['docker', 'run', '-d', '--user', '0:0', '--network', 'host', '--label', 'proxy-deploy.probe=true',
            '--entrypoint', entry, '-v', f'{path}:/probe.json:ro', definition['image'], *command])
        if not re.fullmatch(r'[a-f0-9]{64}', cid):
            raise RuntimeError('Нет ID проверочного клиента.')
        for _ in range(30):
            try:
                base.tcp_probe(port)
                break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError('Проверочный клиент не запустился.')
        base.https_probe(port, name)
    except BaseException:
        if cid:
            base.capture_container(cid, name + ' probe')
        raise
    finally:
        if cid and re.fullmatch(r'[a-f0-9]{64}', cid):
            run(['docker', 'rm', '-f', cid])
        path.unlink(missing_ok=True)


def recover():
    journal = ROOT / 'pending.json'
    if not journal.exists():
        return
    pending = base.read_json(journal)
    print('[!] Откат незавершённого добавления дополнительных сервисов.', flush=True)
    # Restore routes first. Existing connections and base containers remain untouched.
    restore_files(pending['files'])
    run(['nginx', '-t'])
    run(['systemctl', 'reload', 'nginx'])
    compose(pending['candidate'], 'rm', '--stop', '--force', *pending['added'])
    journal.unlink()


def check(s):
    if not s['services']:
        return
    if ROOT.joinpath('pending.json').exists():
        raise RuntimeError('Есть незавершённая операция; повторите --add для безопасного отката.')
    if MAP.read_text() != routes(s) or stream_with_include(STREAM.read_text()) != STREAM.read_text():
        raise RuntimeError('SNI-маршруты дополнительных сервисов изменены/отсутствуют.')
    manifest = base.read_json(ROOT / 'compose.json')
    with tempfile.TemporaryDirectory(prefix='proxy-extra-probe-') as tmp:
        for name, item in s['services'].items():
            probe(name, item, manifest['services'][name], Path(tmp))
            print(f'[+] {name}: HTTPS-запрос через реальный клиент выполнен.', flush=True)


def add(requested, cloudflare=False):
    legacy = base.read_json(base.ROOT / 'state.json')
    base.validate(legacy)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    recover()
    state_path = ROOT / 'state.json'
    old = base.read_json(state_path) if state_path.exists() else {'schema': 1, 'services': {}}
    validate(old, legacy)
    register(old)
    dns_template = old.get('dns_template') or legacy.get('dns_template')
    if cloudflare:
        import cloudflare_dns as dns
        if not dns_template and not legacy.get('cloudflare_zone'):
            dns_template = dns.template()
    state = collect(old, requested, legacy, dns_template)
    register(state)
    added = sorted(set(state['services']) - old['services'].keys())
    if cloudflare:
        zone = legacy.get('cloudflare_zone') or dns_template['zone']
        dns.ensure(zone, [state['services'][name]['domain'] for name in requested],
                   legacy['public_ips'])
    if not added:
        print('[+] Компоненты уже установлены; настройки, секреты и контейнеры сохраняются.', flush=True)
        check(state)
        export_profiles(state)
        return
    # Fail before starting a Go build on a host with little available memory.
    # Limits compilation parallelism as well; existing services retain their resources.
    if 'naive' in added:
        memory = Path('/proc/meminfo').read_text()
        available = re.search(r'^MemAvailable:\s+(\d+) kB$', memory, re.M)
        if not available or int(available.group(1)) < 800 * 1024:
            raise RuntimeError('Для сборки NaiveProxy нужно минимум 800 MiB доступной RAM. '
                               'Существующие сервисы не изменены.')
    before = core_snapshot()
    for name in ('mtg', 'hysteria'):
        if name in legacy['selected'] and before['containers'].get(name, (None,) * 4)[3] != 'running':
            raise RuntimeError(f'{name} не работает до добавления; сначала проверьте исходную установку.')
    old_manifest = (base.read_json(ROOT / 'compose.json') if (ROOT / 'compose.json').exists()
                    else {'name': PROJECT, 'services': {}})
    if set(old_manifest['services']) != set(old['services']):
        raise RuntimeError('Состав Compose и сохранённого состояния не совпадает.')
    if old['services'] and MAP.read_text() != routes(old):
        raise RuntimeError('Существующие маршруты изменены вручную; автоматическая перезапись запрещена.')
    stream = stream_with_include(STREAM.read_text())
    run(['nginx', '-t'])
    for name in added:
        item = state['services'][name]
        actual = base.resolve(item['domain'])
        if not actual or not actual.issubset(set(legacy['public_ips'])):
            raise ValueError(f'DNS {item["domain"]} должен указывать только на IP этого VPS.')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', PORTS[name]))
        # Existing port 80 default server already exposes the shared ACME webroot.
        print(f'[+] Сертификат {item["domain"]}', flush=True)
        run(['certbot', 'certonly', '--webroot', '-w', '/var/www/proxy-acme',
            '-d', item['domain'], '--cert-name', item['domain'], '--email', legacy['email'],
            '--agree-tos', '--non-interactive', '--keep-until-expiring', '--no-directory-hooks'], 300)
        run(['openssl', 'x509', '-in', f'/etc/letsencrypt/live/{item["domain"]}/fullchain.pem',
             '-noout', '-checkhost', item['domain'], '-checkend', '604800'])
    release = Path(tempfile.mkdtemp(prefix='release-', dir=ROOT))
    manifest = copy.deepcopy(old_manifest)
    for name in added:
        directory = release / name
        directory.mkdir(mode=0o700)
        item = state['services'][name]
        if name == 'naive':
            image = build_naive(directory)
            write_text(directory / 'Caddyfile', caddy_config(item))
        else:
            image = pull(XRAY_IMAGE)
            base.write_json(directory / 'xhttp.json', xray_config(item))
        definition = service_definition(name, item, image, directory)
        manifest['services'][name] = definition
        volumes = [arg for mount in definition['volumes'] for arg in ('-v', mount)]
        cmd = (['validate', '--config', '/config/Caddyfile', '--adapter', 'caddyfile']
               if name == 'naive' else ['run', '-test', '-c', '/config/xhttp.json'])
        run(['docker', 'run', '--rm', '--user', '0:0', '--network', 'none', *volumes, image, *cmd])
    candidate = release / 'compose.json'
    base.write_json(candidate, manifest)
    compose(candidate, 'config', '-q')
    saved = snapshot_files([STREAM, MAP, HOOK, state_path, ROOT / 'compose.json',
                            base.ROOT / 'credentials.txt', ROOT / 'credentials.txt', ROOT / 'naive-client.json'])
    base.write_json(ROOT / 'pending.json', {'files': saved, 'candidate': str(candidate), 'added': added})
    try:
        compose(candidate, 'up', '-d', '--no-deps', *added)
        write_text(MAP, routes(state), 0o644)
        write_text(STREAM, stream, 0o644)
        run(['nginx', '-t'])
        run(['systemctl', 'reload', 'nginx'])
        for name in added:
            probe(name, state['services'][name], manifest['services'][name], release)
            print(f'[+] {name}: клиентская проверка пройдена.', flush=True)
        if core_snapshot() != before:
            raise RuntimeError('Исходные контейнеры/конфигурации изменились во время установки; проверьте журнал.')
        base.write_json(ROOT / 'compose.json', manifest)
        base.write_json(state_path, state)
        write_text(HOOK, renew_hook(state), 0o700)
        export_profiles(state)
        (ROOT / 'pending.json').unlink()
    except BaseException:
        for name in added:
            try:
                cid = compose(candidate, 'ps', '-aq', name)
                if cid:
                    base.capture_container(cid, name + ' before rollback')
            except Exception:
                pass
        recover()
        raise
    print(f'[+] Готово. Исходные контейнеры и настройки сохранены. Профили: {base.ROOT}/credentials.txt', flush=True)
    print('[+] Внешнюю доступность проверьте с вашего ПК/телефона; локальный тест её не подтверждает.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--add')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--cloudflare', action='store_true')
    args = parser.parse_args()
    if args.check and args.cloudflare:
        raise ValueError('--check нельзя совмещать с --cloudflare.')
    base.DIAGNOSTIC_PATH = os.environ.get('PROXY_DEPLOY_LOG')
    for path in (base.ROOT / 'state.json', ROOT / 'state.json', ROOT / 'pending.json'):
        if path.exists() and (path.is_symlink() or path.stat().st_uid != 0
                              or path.stat().st_mode & 0o077):
            raise RuntimeError(f'{path}: нужен обычный файл root с правами 600.')
    if args.check:
        if (ROOT / 'pending.json').exists():
            raise RuntimeError('Есть незавершённое добавление; повторите --add для восстановления.')
        s = base.read_json(ROOT / 'state.json')
        validate(s, base.read_json(base.ROOT / 'state.json'))
        register(s)
        check(s)
    else:
        requested = (args.add or '').split(',')
        if not requested or set(requested) - PORTS.keys() or len(set(requested)) != len(requested):
            raise ValueError('Используйте --add naive,xhttp, --add naive или --add xhttp.')
        add(requested, args.cloudflare)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        base.diagnostic('extras failed', str(exc))
        print('[ОШИБКА] ' + base.redact(str(exc) or 'Операция прервана.'), file=sys.stderr)
        sys.exit(1)

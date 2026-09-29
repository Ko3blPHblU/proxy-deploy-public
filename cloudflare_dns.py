#!/usr/bin/env python3
"""Opt-in, create-only Cloudflare DNS. API credentials live in memory only."""
import argparse
import getpass
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

import proxy_config as base

ROLES = {'fallback_domain': 'www', 'mtg_domain': 'tg', 'panel_domain': 'panel',
         'hy_domain': 'hy', 'reality_address': 'reality', 'naive': 'naive', 'xhttp': 'xhttp'}


def validate_template(template):
    zone = base.domain(template['zone'])
    prefix = template['prefix']
    if zone != template['zone'] or (prefix and not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?', prefix)):
        raise ValueError('Некорректная зона/префикс Cloudflare.')
    for role in ROLES:
        hostname(template, role)
    return template


def template(saved=None):
    if saved:
        return validate_template(dict(saved))
    zone = base.ask_domain('Зона Cloudflare (например example.com)')
    prefix = input('Метка VPS в именах (например vps1; Enter — без метки): ').strip().lower()
    return validate_template({'zone': zone, 'prefix': prefix})


def hostname(settings, role):
    label = ROLES[role] + ('-' + settings['prefix'] if settings['prefix'] else '')
    return base.domain(label + '.' + settings['zone'])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the Authorization header to another endpoint.


class Cloudflare:
    def __init__(self, token):
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', token):
            raise ValueError('Некорректный формат API-токена Cloudflare.')
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, data=None):
        if method not in ('GET', 'POST') or not path.startswith('/zones'):
            raise ValueError('Разрешены только чтение и создание DNS-записей.')
        req = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
            data=None if data is None else json.dumps(data).encode(), method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=25) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            # Response bodies/headers may reflect credentials. Never log or display them.
            status = exc.code
            exc.close()
            raise RuntimeError(f'Cloudflare HTTP {status}. Проверьте токен, права зоны/DNS '
                               'и лимиты API. Создание не повторяется автоматически.') from None
        except (OSError, ValueError, urllib.error.URLError):
            raise RuntimeError('Cloudflare: ответ не получен или некорректен. '
                               'Запись могла быть создана; повторный запуск сначала проверит её.') from None
        if not isinstance(result, dict) or result.get('success') is not True:
            raise RuntimeError('Cloudflare отклонил запрос (success != true). Проверьте права токена.')
        return result

    def listing(self, path, query):
        rows = []
        for page in range(1, 1001):
            result = self.request('GET', path + '?' + urllib.parse.urlencode({**query, 'page': page}))
            if not isinstance(result.get('result'), list):
                raise RuntimeError('Cloudflare: некорректный список записей.')
            rows.extend(result['result'])
            pages = result.get('result_info', {}).get('total_pages')
            if not isinstance(pages, int) or pages < 0:
                raise RuntimeError('Cloudflare: отсутствует информация о страницах; проверка прервана.')
            if page >= pages:
                return rows
        raise RuntimeError('Cloudflare: слишком много страниц; изменения не выполнены.')

    def zone(self, name):
        zones = self.listing('/zones', {'name': name, 'per_page': 50})
        matching = [z for z in zones if z.get('name') == name and z.get('status') == 'active']
        if len(matching) != 1 or not re.fullmatch(r'[a-f0-9]{32}', matching[0].get('id', '')):
            raise RuntimeError('Не найдена единственная активная зона. Нужен Zone Read для выбранной зоны.')
        return matching[0]['id']

    def records(self, zone_id, **filters):
        if 'name' in filters:
            # Official Cloudflare client serializes nested query fields with dots.
            filters['name.exact'] = filters.pop('name')
        return self.listing(f'/zones/{zone_id}/dns_records', {**filters, 'per_page': 100})


def missing_records(name, records, addresses):
    """Refuse conflicting A/AAAA/CNAME/NS without changing any existing record."""
    found = set()
    for record in records:
        if record.get('name', '').rstrip('.').lower() != name:
            raise RuntimeError('Cloudflare вернул запись другого имени; изменения отменены.')
        kind = record.get('type')
        if kind in ('CNAME', 'NS'):
            raise ValueError(f'Конфликт {name}: существующая {kind}; запись сохранена.')
        if kind not in ('A', 'AAAA'):
            continue  # TXT, MX and unrelated data are never modified.
        address = ipaddress.ip_address(record['content'])
        if (kind != ('A' if address.version == 4 else 'AAAA') or str(address) not in addresses
                or record.get('proxied') is not False):
            raise ValueError(f'Конфликт {name}: {kind} {address}, proxied={record.get("proxied")}. '
                             'Существующая запись сохранена; исправьте её вручную.')
        found.add(str(address))
    return [{'type': 'A' if ipaddress.ip_address(ip).version == 4 else 'AAAA',
             'name': name, 'content': ip, 'ttl': 1, 'proxied': False,
             'comment': 'Created by proxy-deploy'} for ip in sorted(addresses - found)]


def provision(client, zone, names, ips):
    zone = base.domain(zone)
    names = sorted(set(names))
    addresses = {str(ipaddress.ip_address(ip)) for ip in ips}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('Для DNS нужны публичные IP VPS.')
    for name in names:
        if base.domain(name) != name or not name.endswith('.' + zone):
            raise ValueError(f'{name}: имя должно быть поддоменом зоны {zone}.')
    zone_id = client.zone(zone)
    delegations = client.records(zone_id, type='NS')
    planned = []
    # Validate ALL names before the first write: a later conflict causes zero writes.
    for name in names:
        for record in delegations:
            delegated = record.get('name', '').rstrip('.').lower()
            if delegated and delegated != zone and (name == delegated or name.endswith('.' + delegated)):
                raise ValueError(f'{name}: подзона {delegated} делегирована через NS; изменения отменены.')
        missing = missing_records(name, client.records(zone_id, name=name), addresses)
        planned.extend(missing)
        print(f'[DNS] {name}: {len(missing)} новых A/AAAA; совпадающие записи сохраняются.', flush=True)
    created = []
    try:
        for record in planned:
            # Re-read immediately before mutation to catch most concurrent edits.
            current = missing_records(record['name'], client.records(zone_id, name=record['name']), addresses)
            if not any(r['content'] == record['content'] for r in current):
                continue
            client.request('POST', f'/zones/{zone_id}/dns_records', record)
            created.append(record)
            print(f'[DNS] Создана {record["type"]} {record["name"]} -> {record["content"]} (DNS only).', flush=True)
        for name in names:
            if missing_records(name, client.records(zone_id, name=name), addresses):
                raise RuntimeError(f'{name}: Cloudflare не подтвердил все адреса после создания.')
    except BaseException:
        print('[DNS] Операция прервана. Уже созданные записи сохраняются. '
              'Повторный запуск проверит их; автоматического удаления/перезаписи нет.', flush=True)
        raise
    return created


def public_addresses(name, timeout=10):
    """Check both families over public DNS, including unexpected AAAA on IPv4-only VPS."""
    found = set()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for kind, number in (('A', 1), ('AAAA', 28)):
        url = 'https://dns.google/resolve?' + urllib.parse.urlencode({'name': name, 'type': kind})
        with opener.open(url, timeout=timeout) as response:
            result = json.load(response)
        if result.get('Status') not in (0, 3):
            raise ValueError('Публичный DNS пока не подтвердил запись.')
        for row in result.get('Answer', []):
            if row.get('type') in (1, 28):
                address = ipaddress.ip_address(row['data'])
                if row['type'] != (1 if address.version == 4 else 28):
                    raise ValueError('Некорректный DNS-ответ.')
                found.add(str(address))
    return found


def local_addresses(name, timeout):
    # libc getaddrinfo does not obey socket.setdefaulttimeout. Bound it in a child.
    result = subprocess.run([sys.executable, '-c',
        'import socket,json,sys; print(json.dumps(sorted({r[4][0] for r in '
        'socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))', name],
        capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError('Резолвер VPS пока не подтвердил запись.')
    return {str(ipaddress.ip_address(ip)) for ip in json.loads(result.stdout)}


def wait_dns(names, ips, timeout=300):
    expected = {str(ipaddress.ip_address(ip)) for ip in ips}
    deadline = time.monotonic() + timeout
    pending = set(names)
    while pending and time.monotonic() < deadline:
        for name in sorted(pending):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                if (public_addresses(name, timeout=min(5, remaining / 3)) == expected
                        and local_addresses(name, timeout=min(5, remaining / 3)) == expected):
                    pending.remove(name)
                    print(f'[DNS] {name}: публичный DNS и резолвер VPS подтвердили адреса.', flush=True)
            except (OSError, ValueError, urllib.error.URLError, subprocess.TimeoutExpired):
                pass
        if pending:
            print('[DNS] Ожидаю обновления: ' + ', '.join(sorted(pending)), flush=True)
            time.sleep(min(10, max(0, deadline - time.monotonic())))
    if pending:
        raise RuntimeError('DNS не подтвердился за отведённое время: ' + ', '.join(sorted(pending)) +
                           '. Записи сохранены; повторите запуск позднее. Сертификаты ещё не запрошены.')


def ensure(zone, names, ips):
    if not names:
        return
    if not sys.stdin.isatty():
        raise RuntimeError('Для скрытого ввода Cloudflare API Token нужен интерактивный терминал.')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        token = getpass.getpass('Cloudflare API Token (Zone Read + DNS Edit только этой зоны): ')
    client = Cloudflare(token)
    token = None
    try:
        provision(client, zone, names, ips)
    finally:
        client.token = ''
    wait_dns(names, ips)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', required=True)
    args = parser.parse_args()
    s = base.read_json(args.state)
    base.validate(s)
    saved = s.get('dns_template')
    zone = s.get('cloudflare_zone') or (validate_template(saved)['zone'] if saved
                                       else base.ask_domain('Зона Cloudflare для сохранённых доменов'))
    names = base.owned_domains(s)
    extra_path = Path(args.state).parent / 'extras' / 'state.json'
    if extra_path.exists():
        from proxy_extras import validate
        extra = base.read_json(extra_path)
        validate(extra, s)
        names.extend(item['domain'] for item in extra['services'].values())
    ensure(zone, names, s['public_ips'])


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('[ОШИБКА DNS] ' + str(exc or 'Операция прервана.'), file=sys.stderr)
        sys.exit(1)

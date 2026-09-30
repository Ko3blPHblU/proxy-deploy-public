#!/usr/bin/env python3
"""Disposable Ubuntu CI host only. Real Caddy/Xray/Naive clients and Nginx.

ACME issuance/DNS are replaced by a local CA; never run on a production VPS.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch

import proxy_config as base
import proxy_extras as extra
import cloudflare_dns as dns
import proxy_subscription as subscription
from test_cloudflare_dns import FakeCloudflare
from test_proxy_config import state


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('Disposable GitHub Actions root runner required.')
    root = Path('/opt/proxy-deploy')
    root.mkdir(mode=0o700)
    extra.ROOT.mkdir(mode=0o700)
    base.DIAGNOSTIC_PATH = '/tmp/proxy-extras-ci.log'
    legacy = state()
    legacy['selected'] = ['mtg', 'hysteria']
    legacy['dns_template'] = {'zone': 'example.com', 'prefix': ''}
    base.write_json(root / 'state.json', legacy)
    run = extra.run
    ca = Path('/tmp/extras-ca.crt')
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
         '-subj', '/CN=Extras CI CA', '-keyout', '/tmp/extras-ca.key', '-out', ca])
    domains = ['naive.example.com', 'xhttp.example.com']
    for domain in [*domains, legacy['hy_domain'], legacy['fallback_domain']]:
        directory = Path('/etc/letsencrypt/live') / domain
        directory.mkdir(parents=True)
        run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + domain,
             '-keyout', directory / 'privkey.pem', '-out', '/tmp/extra.csr'])
        Path('/tmp/extra.ext').write_text('subjectAltName=DNS:' + domain + '\n')
        run(['openssl', 'x509', '-req', '-in', '/tmp/extra.csr', '-CA', ca,
             '-CAkey', '/tmp/extras-ca.key', '-CAcreateserial', '-days', '10',
             '-extfile', '/tmp/extra.ext', '-out', directory / 'fullchain.pem'])
    extra.HOOK.parent.mkdir(parents=True, exist_ok=True)
    extra.STREAM.write_text(base.nginx_stream(legacy))
    subscription.HTTP.write_text(base.nginx_http(legacy, True))
    Path('/etc/nginx/nginx.conf').write_text('''include /etc/nginx/modules-enabled/*.conf;
events {}
http { include /etc/nginx/conf.d/proxy-deploy-http.conf; }
include /etc/nginx/proxy-deploy-stream.conf;
''')
    run(['nginx', '-t'])
    # The daemon inherits stdout/stderr; do not wait on captured pipes it keeps open.
    subprocess.run(['nginx'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=15)
    images = {name: extra.pull(base.IMAGES[name]) for name in legacy['selected']}
    base.write_json(root / 'images.json', images)
    base.generate(legacy, images, root)
    run(['docker', 'compose', '-p', 'proxy-deploy', '-f', root / 'compose.json', 'up', '-d'])
    initial = extra.core_snapshot()
    original_docker_output = base.docker_output

    def test_docker_output(args, timeout=60):
        if args[:2] == ['run', '-d'] and 'proxy-deploy.probe=true' in args:
            args = [*args[:2], '-e', 'SSL_CERT_FILE=/test-ca.pem', '-v', f'{ca}:/test-ca.pem:ro', *args[2:]]
        return original_docker_output(args, timeout)

    def verify_legacy():
        mtg_id = run(['docker', 'compose', '-p', 'proxy-deploy', '-f', root / 'compose.json', 'ps', '-q', 'mtg'])
        base.mtg_probe(legacy, mtg_id)
        with patch.object(base, 'docker_output', side_effect=test_docker_output):
            base.client_probe(legacy, images, 'hysteria', Path('/tmp/hy-ci-probe.json'))
        assert extra.core_snapshot() == initial

    verify_legacy()
    dns_api = FakeCloudflare()

    def test_dns(zone, names, ips):
        dns.provision(dns_api, zone, names, ips)
        # DNS propagation and ACME use local fixtures; no external zone is modified.

    def test_run(args, timeout=120):
        args = [str(a) for a in args]
        if args[0] == 'certbot':
            assert '--no-directory-hooks' in args
            return ''  # The CA above replaces ACME only in this test.
        if args[:3] == ['systemctl', 'reload', 'nginx']:
            return run(['nginx', '-s', 'reload'])
        if args[:3] == ['docker', 'run', '-d'] and 'proxy-deploy.probe=true' in args:
            args[3:3] = ['-e', 'SSL_CERT_FILE=/test-ca.pem', '-v', f'{ca}:/test-ca.pem:ro']
        return run(args, timeout)

    with patch.object(extra, 'run', side_effect=test_run), \
            patch.object(dns, 'ensure', side_effect=test_dns), \
            patch.object(base, 'resolve', return_value={'8.8.8.8'}), \
            patch.object(base, 'ask_domain', side_effect=domains):
        # Add first service, then deliberately fail the second after its start.
        extra.add(['naive'], cloudflare=True)
        first = base.read_json(extra.ROOT / 'state.json')
        first_credentials = (root / 'credentials.txt').read_bytes()
        assert b'NaiveProxy:' in first_credentials
        assert b'Hysteria:' in first_credentials
        assert not (extra.ROOT / 'credentials.txt').exists()
        naive_id = extra.compose(extra.ROOT / 'compose.json', 'ps', '-q', 'naive')
        first_routes = extra.MAP.read_bytes()
        real_probe = extra.probe
        def fail_xhttp(name, *args):
            if name == 'xhttp':
                raise RuntimeError('injected client failure')
            return real_probe(name, *args)
        with patch.object(extra, 'probe', side_effect=fail_xhttp):
            try:
                extra.add(['xhttp'], cloudflare=True)
            except RuntimeError as exc:
                assert 'injected client failure' in str(exc)
            else:
                raise AssertionError('Failure was not propagated')
        assert extra.MAP.read_bytes() == first_routes
        assert base.read_json(extra.ROOT / 'state.json') == first
        assert (root / 'credentials.txt').read_bytes() == first_credentials
        assert extra.compose(extra.ROOT / 'compose.json', 'ps', '-q', 'naive') == naive_id
        assert extra.core_snapshot() == initial
        verify_legacy()
        extra.check(first)

    with patch.object(extra, 'run', side_effect=test_run), \
            patch.object(dns, 'ensure', side_effect=test_dns), \
            patch.object(base, 'resolve', return_value={'8.8.8.8'}), \
            patch.object(base, 'ask_domain', return_value='xhttp.example.com'):
        extra.add(['xhttp'], cloudflare=True)
        committed = base.read_json(extra.ROOT / 'state.json')
        all_credentials = (root / 'credentials.txt').read_bytes()
        assert b'NaiveProxy:' in all_credentials and b'XHTTP:' in all_credentials
        ids_before = extra.compose(extra.ROOT / 'compose.json', 'ps', '-q')
        extra.add(['naive', 'xhttp'], cloudflare=True)
        assert base.read_json(extra.ROOT / 'state.json') == committed
        assert (root / 'credentials.txt').read_bytes() == all_credentials
        assert extra.compose(extra.ROOT / 'compose.json', 'ps', '-q') == ids_before
        assert extra.core_snapshot() == initial
        # Exercise real certificate reload/restart commands, never the legacy project.
        hook = extra.renew_hook(committed)
        hook_path = Path('/tmp/test-extra-renew-hook')
        hook_path.write_text(hook)
        for domain in domains:
            subprocess.run(['bash', hook_path], check=True, timeout=150,
                           env={**os.environ, 'RENEWED_LINEAGE': '/etc/letsencrypt/live/' + domain})
        extra.check(committed)
        verify_legacy()
        assert len(dns_api.writes) == 2  # Failure/retry never duplicates DNS or deletes it.
    # Real TLS subscription endpoint and systemd refresh; no changes to proxy containers.
    import fcntl
    import ssl
    original_verify = subscription.verify
    trusted_context = ssl.create_default_context(cafile=str(ca))
    before_subscription = extra.core_snapshot()
    with open('/run/lock/proxy-deploy.lock', 'w') as lock, \
            patch.object(subscription, 'run', side_effect=test_run), \
            patch.object(subscription, 'verify', side_effect=lambda s, settings, bodies:
                         original_verify(s, settings, bodies, context=trusted_context)):
        fcntl.flock(lock, fcntl.LOCK_EX)
        subscription.install()
        settings_before = base.read_json(subscription.ROOT / 'state.json')
        credentials_before = (root / 'credentials.txt').read_bytes()
        subscription.install()
        assert base.read_json(subscription.ROOT / 'state.json') == settings_before
        assert (root / 'credentials.txt').read_bytes() == credentials_before
        http_before = subscription.HTTP.read_bytes()
        with patch.object(subscription, 'verify', side_effect=RuntimeError('injected HTTPS failure')):
            try:
                subscription.install()
            except RuntimeError:
                pass
            else:
                raise AssertionError('Subscription error was swallowed')
        assert subscription.HTTP.read_bytes() == http_before
        assert (root / 'credentials.txt').read_bytes() == credentials_before
        assert not (subscription.ROOT / 'pending.json').exists()
        old_settings = settings_before
        subscription.install(rotate=True)
        settings_before = base.read_json(subscription.ROOT / 'state.json')
        assert subscription.token_from(settings_before) != subscription.token_from(old_settings)
        for client in ('v2rayn', 'v2rayng'):
            assert not (subscription.PUBLIC / subscription.token_from(old_settings) / (client + '.txt')).exists()
        try:
            original_verify(legacy, old_settings, subscription.load_profiles()[2], context=trusted_context)
        except RuntimeError:
            pass  # Old URLs no longer return the subscription.
        else:
            raise AssertionError('Rotated URLs still work')
        fcntl.flock(lock, fcntl.LOCK_UN)
    run(['systemctl', 'start', subscription.UNIT.name])
    _, _, bodies = subscription.load_profiles()
    original_verify(legacy, settings_before, bodies, context=trusted_context)
    assert extra.core_snapshot() == before_subscription
    verify_legacy()
    print('PASS: clients, rollback, repeat, certificate reload, HTTPS subscriptions and systemd refresh; mtg/Hysteria preserved.')


if __name__ == '__main__':
    main()

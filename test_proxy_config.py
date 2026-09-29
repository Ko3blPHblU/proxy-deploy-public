"""Offline tests. No Docker, network access, system changes or real credentials."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

import proxy_config as config


def state():
    return {'schema': 1, 'selected': ['mtg', 'xui', 'hysteria'], 'ipv6': False,
        'public_ips': ['8.8.8.8'], 'fallback_domain': 'www.example.com',
        'panel_domain': 'panel.example.com', 'hy_domain': 'hy.example.com',
        'mtg_domain': 'tg.example.com', 'reality_address': 'vpn.example.com',
        'mtg_sni': 'mask.example.org', 'reality_sni': 'target.example.org',
        'mtg_secret': 'ee' + 'ab' * 16 + 'mask.example.org'.encode().hex(),
        'email': 'test@example.com', 'panel_user': 'u_1234567890123456',
        'panel_password': 'example-password-123456789', 'panel_path': '/12345678901234567890/',
        'uuid': '12345678-1234-4234-8234-123456789012', 'short_id': '0123456789abcdef',
        'hy_password': 'quotes" slash\\ dollar$ colon: Unicodeпароль',
        'reality_private': 'a' * 43, 'reality_public': 'b' * 43}


class ConfigurationTests(unittest.TestCase):
    def test_domains_reject_config_injection_and_urls(self):
        for value in ['x.example;}', 'https://example.com', '-a.example', 'a..com',
                      'a.example\ninclude /tmp/pwn;', 'a.example:443', '8.8.8.8']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.domain(value)

    def test_route_collision_fails(self):
        s = state()
        s['reality_sni'] = s['mtg_sni']
        with self.assertRaises(ValueError):
            config.validate(s)

    def test_secret_must_match_mtg_sni(self):
        s = state()
        s['mtg_sni'] = 'other.example.org'
        with self.assertRaises(ValueError):
            config.validate(s)

    def test_no_accidental_ipv6(self):
        s = state()
        s['public_ips'].append('2606:4700:4700::1111')
        with self.assertRaises(ValueError):
            config.validate(s)

    def test_generation_round_trips_password_and_isolates_ports(self):
        s = state()
        images = {key: value.split(':')[0] + '@sha256:' + 'a' * 64
                  for key, value in config.IMAGES.items()}
        with tempfile.TemporaryDirectory() as tmp:
            config.generate(s, images, tmp)
            hy = config.read_json(Path(tmp) / 'hysteria.json')
            self.assertEqual(hy['auth']['password'], s['hy_password'])
            self.assertIn('/hy.example.com/', hy['tls']['cert'])
            compose = config.read_json(Path(tmp) / 'compose.json')['services']
            for name in ('mtg', 'xui'):
                self.assertTrue(all(p.startswith('127.0.0.1:') for p in compose[name]['ports']))
            self.assertNotIn('cap_add', compose['xui'])
            before = (Path(tmp) / 'mtg.toml').read_bytes()
            config.generate(s, images, tmp)
            self.assertEqual(before, (Path(tmp) / 'mtg.toml').read_bytes())

    def test_mutable_image_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            config.generate(state(), config.IMAGES, tmp)

    def test_correct_sni_and_tls_termination(self):
        s = state()
        stream, http = config.nginx_stream(s), config.nginx_http(s, True)
        self.assertIn('mask.example.org 127.0.0.1:8443;', stream)
        self.assertNotIn('tg.example.com 127.', stream)
        self.assertIn('target.example.org 127.0.0.1:10443;', stream)
        self.assertIn('panel.example.com 127.0.0.1:9444;', stream)
        self.assertIn('listen 127.0.0.1:9444 ssl;', http)
        self.assertIn('proxy_pass http://127.0.0.1:2053;', http)
        self.assertNotIn('listen [::]', stream)
        s['ipv6'] = True
        self.assertIn('listen [::]:443;', config.nginx_stream(s))

    def test_bootstrap_never_references_missing_certificates(self):
        text = config.nginx_http(state(), False)
        self.assertIn('listen 80;', text)
        self.assertIn('/.well-known/acme-challenge/', text)
        self.assertNotIn('ssl_certificate', text)

    def test_links_use_public_address_and_preserve_special_password(self):
        s = state()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'credentials.txt'
            config.credentials(s, path)
            text = path.read_text(encoding='utf-8')
        self.assertIn('server=tg.example.com&port=443', text)
        uri = next(line.split(': ', 1)[1] for line in text.splitlines() if line.startswith('Hysteria:'))
        self.assertEqual(urllib.parse.unquote(urllib.parse.urlsplit(uri).username), s['hy_password'])
        self.assertNotIn('127.0.0.1', text)

    def test_dns_mismatch_rejected_before_tls(self):
        with patch.object(config, 'resolve', return_value={'1.1.1.1'}), self.assertRaises(ValueError):
            config.preflight(state())

    def test_timeout_does_not_reveal_secret(self):
        secret = 'DO-NOT-LOG-THIS'
        with patch.object(config.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
                ['docker', 'setting', '-password', secret], 1)):
            with self.assertRaises(RuntimeError) as caught:
                config.docker_output(['setting', '-password', secret])
        self.assertNotIn(secret, str(caught.exception))

    def test_failed_client_probe_removes_container_and_secret_file(self):
        cid = 'a' * 64
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'probe.json'
            with patch.object(config.socket, 'socket'), patch.object(config, 'tcp_probe'), \
                    patch.object(config, 'docker_output', side_effect=[cid, '']) as docker, \
                    patch.object(config.subprocess, 'run') as run:
                run.return_value.returncode = 1
                with self.assertRaises(RuntimeError):
                    config.client_probe(state(), config.IMAGES, 'hysteria', target)
                self.assertEqual(docker.call_args_list[-1].args[0], ['rm', '-f', cid])
            self.assertFalse(target.exists())

    def test_api_failure_with_http_200_is_still_an_error(self):
        api = config.Panel(state(), 'SECRET-TOKEN')
        with patch.object(api.opener, 'open') as request:
            response = request.return_value.__enter__.return_value
            response.read.return_value = b'{"success": false, "msg": "failure"}'
            with self.assertRaises(RuntimeError):
                api.call('inbounds/add', {})


class PanelTests(unittest.TestCase):
    def output(self, args, timeout=60):
        if '-show' in args:
            return 'hasDefaultCredential: false\nport: 2053\nwebBasePath: /12345678901234567890/\n'
        return 'apiToken: TEST-TOKEN\n'

    def inbound(self):
        s = state()
        return {'id': 1, 'remark': 'proxy-deploy-reality', 'port': 10443,
                'enable': True, 'protocol': 'vless', 'listen': '0.0.0.0',
                'settings': json.dumps({'clients': [{'id': s['uuid'], 'enable': True,
                                                    'flow': 'xtls-rprx-vision'}]}),
                'streamSettings': json.dumps({'network': 'tcp', 'security': 'reality',
                    'realitySettings': {'serverNames': [s['reality_sni']],
                        'privateKey': s['reality_private'], 'shortIds': [s['short_id']],
                        'target': s['reality_sni'] + ':443'}})}

    def test_repeat_does_not_change_existing_inbound(self):
        with patch.object(config, 'docker_output', self.output), patch.object(config, 'Panel') as cls:
            cls.return_value.call.return_value = [self.inbound()]
            config.panel_api(state(), 'container', '/unused')
            cls.return_value.call.assert_called_once_with('inbounds/list')

    def test_manual_change_is_not_overwritten(self):
        inbound = self.inbound()
        inbound['port'] = 12345
        with patch.object(config, 'docker_output', self.output), patch.object(config, 'Panel') as cls:
            cls.return_value.call.return_value = [inbound]
            with self.assertRaises(RuntimeError):
                config.panel_api(state(), 'container', '/unused')
            cls.return_value.call.assert_called_once_with('inbounds/list')

    def test_default_credentials_block_publication(self):
        with patch.object(config, 'docker_output', return_value='hasDefaultCredential: true'), \
                patch.object(config, 'Panel') as cls:
            with self.assertRaises(RuntimeError):
                config.panel_api(state(), 'container', '/unused')
            cls.assert_not_called()

    def test_create_uses_saved_keys_and_client_identity(self):
        s = state()
        original = copy.deepcopy(s)
        with patch.object(config, 'docker_output', self.output), patch.object(config, 'Panel') as cls:
            cls.return_value.call.side_effect = [[], {}, {}]
            config.panel_api(s, 'container', '/unused')
            calls = cls.return_value.call.call_args_list
            self.assertEqual([c.args[0] for c in calls],
                             ['inbounds/list', 'inbounds/add', 'server/restartXrayService'])
            data = calls[1].args[1]
            self.assertEqual(json.loads(data['settings'])['clients'][0]['id'], s['uuid'])
            self.assertEqual(json.loads(data['streamSettings'])['realitySettings']['privateKey'],
                             s['reality_private'])
        self.assertEqual(s, original)


if __name__ == '__main__':
    unittest.main()

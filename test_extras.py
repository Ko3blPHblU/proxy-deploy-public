"""Offline regression coverage for additive upgrades and targeted rollback."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import proxy_config as base
import proxy_extras as extra
from test_proxy_config import state


def extras():
    return {'schema': 1, 'services': {
        'naive': {'domain': 'naive.example.com', 'user': 'u' * 24, 'password': 'p' * 32},
        'xhttp': {'domain': 'xhttp.example.com', 'uuid': '12345678-1234-4234-8234-123456789abc',
                  'path': '/' + 'a' * 32 + '/'}}}


class ExtrasTests(unittest.TestCase):
    def tearDown(self):
        base.SECRETS.clear()

    def test_repeated_selection_preserves_every_secret_without_prompt(self):
        old = extras()
        with patch.object(base, 'ask_domain', side_effect=AssertionError('unexpected prompt')):
            self.assertEqual(extra.collect(old, ['naive', 'xhttp'], state()), old)

    def test_add_one_preserves_existing_and_legacy_state(self):
        old, legacy = extras(), state()
        del old['services']['xhttp']
        before, legacy_before = copy.deepcopy(old), copy.deepcopy(legacy)
        with patch.object(base, 'ask_domain', return_value='xhttp.example.com'):
            result = extra.collect(old, ['naive', 'xhttp'], legacy)
        self.assertEqual(result['services']['naive'], before['services']['naive'])
        self.assertEqual(old, before)
        self.assertEqual(legacy, legacy_before)
        extra.validate(result, legacy)

    def test_collisions_with_legacy_and_other_extras_rejected(self):
        for domain in ('mask.example.org', 'hy.example.com', 'vpn.example.com', 'xhttp.example.com'):
            s = extras()
            s['services']['naive']['domain'] = domain
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                extra.validate(s, state())

    def test_nginx_extension_preserves_all_original_routes_and_timeouts(self):
        old = base.nginx_stream(state())
        updated = extra.stream_with_include(old)
        self.assertEqual(extra.stream_with_include(updated), updated)
        self.assertEqual(updated.replace(f'        include {extra.MAP};\n', ''), old)
        with self.assertRaises(RuntimeError):
            extra.stream_with_include('custom nginx configuration')

    def test_extra_services_never_publish_udp_or_external_admin_ports(self):
        for name, item in extras()['services'].items():
            s = extra.service_definition(name, item, 'sha256:' + 'a' * 64, Path('/release'))
            self.assertEqual(s['ports'], [f'127.0.0.1:{extra.PORTS[name]}:443'])
            self.assertNotIn('network_mode', s)
            self.assertNotIn('/etc/x-ui', json.dumps(s))

    def test_xhttp_server_and_profile_agree_and_do_not_use_vision(self):
        s = extras()
        inbound = extra.xray_config(s['services']['xhttp'])['inbounds'][0]
        self.assertEqual(inbound['streamSettings']['security'], 'tls')
        self.assertEqual(inbound['streamSettings']['xhttpSettings']['mode'], 'packet-up')
        self.assertNotIn('flow', inbound['settings']['clients'][0])
        with tempfile.TemporaryDirectory() as tmp, patch.object(base, 'ROOT', Path(tmp)), \
                patch.object(extra, 'ROOT', Path(tmp) / 'extras'):
            extra.ROOT.mkdir()
            legacy = state()
            legacy.pop('reality_public')
            base.write_json(base.ROOT / 'state.json', legacy)
            extra.export_profiles(s)
            text = (Path(tmp) / 'credentials.txt').read_text()
            self.assertIn('mode=packet-up', text)
            self.assertIn('@xhttp.example.com:443?', text)
            self.assertNotIn('12443', text)
            self.assertNotIn('flow=', text)

    def test_unified_credentials_migrate_repeat_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(base, 'ROOT', Path(tmp)), \
                patch.object(extra, 'ROOT', Path(tmp) / 'extras'):
            extra.ROOT.mkdir()
            base.write_json(base.ROOT / 'state.json', state())
            target = base.ROOT / 'credentials.txt'
            old = extra.ROOT / 'credentials.txt'
            base.credentials(state(), target)
            old.write_text('old extra credentials')
            before = extra.snapshot_files([target, old])
            extra.export_profiles(extras())
            combined = target.read_text(encoding='utf-8')
            for label in ('Telegram:', 'Панель:', 'VLESS:', 'Hysteria:', 'NaiveProxy:', 'XHTTP:'):
                self.assertEqual(combined.count(label), 1)
            self.assertFalse(old.exists())
            extra.export_profiles(extras())
            self.assertEqual(target.read_text(encoding='utf-8'), combined)
            extra.restore_files(before)
            self.assertEqual(target.read_text(encoding='utf-8'), before[str(target)])
            self.assertEqual(old.read_text(), 'old extra credentials')

    def test_failed_atomic_export_preserves_previous_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'credentials.txt'
            target.write_text('previous credentials')
            with patch.object(Path, 'replace', side_effect=OSError('disk error')):
                with self.assertRaises(OSError):
                    base.credentials(state(), target, extras())
            self.assertEqual(target.read_text(), 'previous credentials')
            self.assertEqual(list(Path(tmp).iterdir()), [target])

    def test_caddy_uses_explicit_cert_and_http2_without_udp_listener(self):
        text = extra.caddy_config(extras()['services']['naive'])
        self.assertIn('auto_https off', text)
        self.assertIn('protocols h1 h2', text)
        self.assertIn('probe_resistance', text)
        self.assertIn(':443, naive.example.com', text)

    def test_renewal_hook_targets_only_renewed_service(self):
        text = extra.renew_hook(extras())
        self.assertIn('restart --no-deps xhttp', text)
        self.assertIn('reload --force', text)
        self.assertNotIn('hysteria', text)
        self.assertNotIn('mtg', text)
        self.assertNotIn(' down', text)
        # Lock only after matching a managed certificate (unrelated issuance cannot deadlock).
        self.assertLess(text.index('case '), text.index('flock'))

    def test_rollback_removes_only_added_service_and_restores_committed_metadata(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(extra, 'ROOT', Path(tmp)):
            live = Path(tmp) / 'old-compose.json'
            live.write_text('new candidate')
            base.write_json(Path(tmp) / 'pending.json', {
                'files': {str(live): 'previous config'}, 'candidate': '/candidate/compose.json',
                'added': ['xhttp']})
            with patch.object(extra, 'run') as run, patch.object(extra, 'compose') as compose:
                extra.recover()
            compose.assert_called_once_with('/candidate/compose.json', 'rm', '--stop', '--force', 'xhttp')
            self.assertEqual(live.read_text(), 'previous config')
            self.assertFalse((Path(tmp) / 'pending.json').exists())
            self.assertEqual(run.call_args_list[-1].args[0], ['systemctl', 'reload', 'nginx'])

    def test_failed_rollback_keeps_journal_for_recovery(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(extra, 'ROOT', Path(tmp)):
            pending = Path(tmp) / 'pending.json'
            base.write_json(pending, {'files': {}, 'candidate': '/candidate.json', 'added': ['naive']})
            with patch.object(extra, 'run'), patch.object(extra, 'compose', side_effect=RuntimeError('offline')):
                with self.assertRaises(RuntimeError):
                    extra.recover()
            self.assertTrue(pending.exists())

    def test_new_secrets_are_redacted(self):
        s = extras()
        extra.register(s)
        for item in s['services'].values():
            for key in ('user', 'password', 'uuid', 'path'):
                if key in item:
                    self.assertNotIn(item[key], base.redact(item[key]))


if __name__ == '__main__':
    unittest.main()

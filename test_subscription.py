"""Subscription privacy and current panel state, using only synthetic credentials."""
import base64
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import proxy_config as base
import proxy_subscription as sub
from test_proxy_config import state
from test_extras import extras


class SubscriptionTests(unittest.TestCase):
    def test_profiles_only_no_admin_private_keys_or_telegram(self):
        s = state()
        result = {k: base64.b64decode(v).decode() for k, v in sub.payloads(s, extras()).items()}
        self.assertEqual(len(result['v2rayn'].splitlines()), 4)
        self.assertEqual(len(result['v2rayng'].splitlines()), 3)
        self.assertIn('naive+https://', result['v2rayn'])
        self.assertNotIn('naive', result['v2rayng'])
        for body in result.values():
            for key in ('panel_user', 'panel_password', 'panel_path', 'reality_private', 'mtg_secret'):
                self.assertNotIn(s[key], body)
            self.assertNotIn('tg://', body)
            self.assertIn('insecure=0', body)
            self.assertIn('allowInsecure=0', body)
            self.assertIn('mode=packet-up', body)

    def test_empty_and_partial_installations(self):
        s = state()
        s['selected'] = ['mtg']
        self.assertEqual(base64.b64decode(sub.payloads(s, {})['v2rayng']), b'\n')
        s['selected'] = ['hysteria']
        body = base64.b64decode(sub.payloads(s, {})['v2rayng']).decode()
        self.assertEqual(len(body.splitlines()), 1)
        self.assertIn('hysteria2://', body)
        self.assertNotIn('vless://', body)

    def test_links_are_stable_and_credentials_exports_keep_them(self):
        settings = {'schema': 1, 'profiles': {'owner': {'token': 'a' * 64}}}
        s = state()
        with tempfile.TemporaryDirectory() as tmp, patch.object(base, 'ROOT', Path(tmp)):
            base.write_json(base.ROOT / 'subscriptions' / 'state.json', settings)
            for _ in range(2):
                target = base.ROOT / 'credentials.txt'
                base.credentials(s, target, extras())
                text = target.read_text(encoding='utf-8')
                for url in sub.links(s, settings).values():
                    self.assertEqual(text.count(url), 1)

    def test_token_cannot_inject_paths(self):
        for token in ('../bad', '', 'a' * 63, 'a' * 65, 'x' * 64):
            with self.assertRaises(ValueError):
                sub.token_from({'schema': 1, 'profiles': {'owner': {'token': token}}})

    def test_nginx_preserves_existing_servers_and_is_idempotent(self):
        original = base.nginx_http(state(), True)
        updated = sub.nginx_config(original)
        self.assertEqual(updated, sub.nginx_config(updated))
        self.assertIn('access_log off;', updated)
        self.assertIn('autoindex off;', updated)
        self.assertIn('Cache-Control "no-store"', updated)
        self.assertIn('proxy_pass http://127.0.0.1:2053', updated)
        self.assertIn('/var/lib/proxy-deploy-subscriptions/', updated)
        with self.assertRaises(RuntimeError):
            sub.nginx_config('custom config')

    def make_db(self, path, client=None, stream=None, enabled=True):
        s = state()
        client = client or {'id': s['uuid'], 'email': 'proxy-deploy-client',
                            'enable': True, 'flow': 'xtls-rprx-vision'}
        stream = stream or {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'privateKey': s['reality_private'], 'serverNames': [s['reality_sni']],
            'shortIds': [s['short_id']], 'settings': {'publicKey': s['reality_public']}}}
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE inbounds (enable, port, protocol, settings, stream_settings, remark)')
            db.execute('INSERT INTO inbounds VALUES (?,?,?,?,?,?)',
                       (enabled, 10443, 'vless', json.dumps({'clients': [client]}),
                        json.dumps(stream), 'proxy-deploy-reality'))

    def test_panel_uuid_update_is_read_without_changing_saved_state_or_db(self):
        s = state()
        before = copy.deepcopy(s)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'x-ui.db'
            identifier = '12345678-1234-4234-8234-123456789999'
            self.make_db(path, {'id': identifier, 'email': 'proxy-deploy-client',
                                'flow': 'xtls-rprx-vision'})
            db_before = path.read_bytes()
            result = sub.reality_from_db(s, path)
            self.assertEqual(result['uuid'], identifier)
            self.assertEqual(path.read_bytes(), db_before)
        self.assertEqual(s, before)

    def test_disabled_removed_and_expired_clients_are_not_exported(self):
        for attributes in ({'enable': False}, {'expiryTime': 1}, {'email': 'another-user'}):
            with self.subTest(attributes=attributes), tempfile.TemporaryDirectory() as tmp:
                client = {'id': state()['uuid'], 'email': 'proxy-deploy-client',
                          'flow': 'xtls-rprx-vision', **attributes}
                path = Path(tmp) / 'x-ui.db'
                self.make_db(path, client)
                self.assertNotIn('xui', sub.reality_from_db(state(), path)['selected'])

    def test_changed_route_fails_instead_of_publishing_invalid_reality(self):
        s = state()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'x-ui.db'
            self.make_db(path)
            s['reality_sni'] = 'new.example.org'
            with self.assertRaises(RuntimeError):
                sub.reality_from_db(s, path)


if __name__ == '__main__':
    unittest.main()

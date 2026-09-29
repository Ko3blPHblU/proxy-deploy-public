"""First-install selection and DNS plan; all inputs are synthetic."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import proxy_config as base
import proxy_extras as extras


class WizardTests(unittest.TestCase):
    def collect(self, answers, domains=(), cloudflare=False, forced=''):
        with tempfile.TemporaryDirectory() as tmp, \
                patch('builtins.input', side_effect=answers), \
                patch.object(base, 'ask_domain', side_effect=domains), \
                patch.object(base.getpass, 'getpass', return_value=''), \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(tmp) / 'state.json'
            base.collect(path, cloudflare, forced)
            return base.read_json(path)

    def test_enter_selects_all_and_creates_complete_dns_plan(self):
        s = self.collect(['', 'example.com', 'vps1', '', '8.8.8.8', 'test@example.com'],
                         ['mask.example.org', 'target.example.org'], cloudflare=True)
        self.assertEqual(s['selected'], ['mtg', 'xui', 'hysteria'])
        self.assertEqual(s['extras_requested'], ['naive', 'xhttp'])
        self.assertEqual(len(base.owned_domains(s)), 7)
        self.assertEqual(s['extra_domains']['xhttp'], 'xhttp-vps1.example.com')
        with patch.object(base, 'ask_domain', side_effect=AssertionError('repeated prompt')):
            added = extras.collect({'schema': 1, 'services': {}}, s['extras_requested'], s)
        self.assertEqual(added['services']['naive']['domain'], 'naive-vps1.example.com')

    def test_each_service_has_independent_domain_without_common_domain(self):
        names = ['www.example.com', 'tg.example.net', 'mask.example.org',
                 'panel.example.com', 'vpn.example.net', 'target.example.org',
                 'hy.example.net', 'naive.example.com', 'xhttp.example.net']
        s = self.collect(['', '', '8.8.8.8', 'test@example.com', ''], names)
        self.assertNotIn('dns_template', s)
        self.assertEqual(s['extra_domains']['xhttp'], 'xhttp.example.net')

    def test_all_nonempty_selection_combinations_validate(self):
        for mask in range(1, 32):
            choice = ' '.join(str(n + 1) for n in range(5) if mask & (1 << n))
            domains = (['mask.example.org'] if mask & 1 else []) + (
                       ['target.example.org'] if mask & 2 else [])
            with self.subTest(choice=choice):
                s = self.collect([choice, 'example.com', '', '8.8.8.8', 'test@example.com', ''], domains)
                base.validate(s)
                with tempfile.TemporaryDirectory() as tmp:
                    images = {name: 'example/image@sha256:' + 'a' * 64 for name in s['selected']}
                    base.generate(s, images, tmp)
                    self.assertEqual(set(base.read_json(Path(tmp) / 'compose.json')['services']),
                                     set(s['selected']))
                    self.assertIn('9443', base.nginx_stream(s))

    def test_custom_cloudflare_names_and_no_base_containers(self):
        s = self.collect(['4 5', '', 'example.com', '8.8.8.8', 'test@example.com'],
                         ['landing.example.com', 'private.example.com', 'proxy.example.com'], True)
        self.assertEqual(s['selected'], [])
        self.assertNotIn('dns_template', s)
        self.assertEqual(s['cloudflare_zone'], 'example.com')

    def test_cloudflare_rejects_other_zone_before_saving(self):
        with self.assertRaises(ValueError):
            self.collect(['5', '', 'example.com', '8.8.8.8', 'test@example.com'],
                         ['www.example.com', 'xhttp.example.net'], True)

    def test_duplicate_service_domain_rejected_before_install(self):
        with self.assertRaises(ValueError):
            self.collect(['4 5', '', '8.8.8.8', 'test@example.com'],
                         ['www.example.com', 'proxy.example.com', 'proxy.example.com'])

    def test_invalid_choice_reprompts_and_explicit_add_is_included(self):
        s = self.collect(['oops', '3', 'example.com', '', '8.8.8.8', 'test@example.com', ''],
                         forced='xhttp')
        self.assertEqual(s['selected'], ['hysteria'])
        self.assertEqual(s['extras_requested'], ['xhttp'])

    def test_check_detects_missing_planned_addons_after_partial_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            plan = {'extras_requested': ['naive', 'xhttp']}
            with self.assertRaisesRegex(RuntimeError, '--add=naive,xhttp'):
                base.check_plan(plan, path)
            base.write_json(path, {'services': {'naive': {}}})
            with self.assertRaisesRegex(RuntimeError, '--add=xhttp'):
                base.check_plan(plan, path)
            base.write_json(path, {'services': {'naive': {}, 'xhttp': {}}})
            base.check_plan(plan, path)
            base.check_plan({}, path)  # Old installations have no initial addon plan.


if __name__ == '__main__':
    unittest.main()

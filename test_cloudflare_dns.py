"""Cloudflare tests use a fake provider; no real zone/token or external writes."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import cloudflare_dns as dns
import proxy_config as base
import proxy_extras as extras
from test_proxy_config import state


class FakeCloudflare:
    def __init__(self, rows=()):
        self.rows = copy.deepcopy(list(rows))
        self.writes = []
        self.fail_after = None

    def zone(self, name):
        return 'a' * 32

    def records(self, zone_id, **filters):
        return [dict(r) for r in self.rows if all(r.get(k) == v for k, v in filters.items())]

    def request(self, method, path, data=None):
        assert method == 'POST'
        if self.fail_after is not None and len(self.writes) >= self.fail_after:
            raise RuntimeError('simulated API outage')
        self.writes.append(dict(data))
        self.rows.append(dict(data))
        return {'success': True, 'result': data}


class CloudflareTests(unittest.TestCase):
    def test_template_names_and_input_validation(self):
        t = dns.validate_template({'zone': 'example.com', 'prefix': 'vps1'})
        self.assertEqual(dns.hostname(t, 'naive'), 'naive-vps1.example.com')
        self.assertEqual(dns.hostname(t, 'reality_address'), 'reality-vps1.example.com')
        for prefix in ('bad.dot', '-bad', 'x' * 41, 'bad;command'):
            with self.assertRaises(ValueError):
                dns.validate_template({'zone': 'example.com', 'prefix': prefix})

    def test_first_creation_dual_stack_and_repeat_without_writes(self):
        api = FakeCloudflare()
        ips = ['8.8.8.8', '2606:4700:4700::1111']
        dns.provision(api, 'example.com', ['hy.example.com', 'tg.example.com'], ips)
        self.assertEqual(len(api.writes), 4)
        self.assertTrue(all(r['proxied'] is False and r['ttl'] == 1 for r in api.writes))
        self.assertEqual(dns.provision(api, 'example.com', ['hy.example.com', 'tg.example.com'], ips), [])
        self.assertEqual(len(api.writes), 4)

    def test_ipv4_only_does_not_create_aaaa(self):
        api = FakeCloudflare()
        dns.provision(api, 'example.com', ['hy.example.com'], ['8.8.8.8'])
        self.assertEqual([r['type'] for r in api.writes], ['A'])

    def test_later_conflict_causes_zero_writes_and_preserves_records(self):
        for conflict in (
            {'type': 'A', 'content': '1.1.1.1', 'proxied': False},
            {'type': 'A', 'content': '8.8.8.8', 'proxied': True},
            {'type': 'AAAA', 'content': '2606:4700:4700::1111', 'proxied': False},
            {'type': 'CNAME', 'content': 'elsewhere.example.org', 'proxied': False}):
            api = FakeCloudflare([{'name': 'z.example.com', **conflict}])
            before = copy.deepcopy(api.rows)
            with self.subTest(conflict=conflict), self.assertRaises(ValueError):
                dns.provision(api, 'example.com', ['a.example.com', 'z.example.com'], ['8.8.8.8'])
            self.assertEqual(api.writes, [])
            self.assertEqual(api.rows, before)

    def test_delegated_subzone_rejected_before_writes(self):
        api = FakeCloudflare([{'name': 'sub.example.com', 'type': 'NS', 'content': 'ns.example.org'}])
        with self.assertRaises(ValueError):
            dns.provision(api, 'example.com', ['naive.sub.example.com'], ['8.8.8.8'])
        self.assertEqual(api.writes, [])

    def test_unrelated_records_remain_intact(self):
        rows = [{'name': 'hy.example.com', 'type': 'TXT', 'content': 'keep-me'},
                {'name': 'other.example.com', 'type': 'A', 'content': '1.1.1.1', 'proxied': True}]
        api = FakeCloudflare(rows)
        dns.provision(api, 'example.com', ['hy.example.com'], ['8.8.8.8'])
        self.assertEqual(api.rows[:2], rows)

    def test_partial_failure_is_recoverable_without_delete_or_duplicate(self):
        api = FakeCloudflare()
        api.fail_after = 1
        with self.assertRaises(RuntimeError):
            dns.provision(api, 'example.com', ['a.example.com', 'b.example.com'], ['8.8.8.8'])
        self.assertEqual(len(api.rows), 1)
        api.fail_after = None
        dns.provision(api, 'example.com', ['a.example.com', 'b.example.com'], ['8.8.8.8'])
        self.assertEqual(len(api.writes), 2)

    def test_out_of_zone_and_private_ip_rejected(self):
        api = FakeCloudflare()
        for name, ips in [('a.other.com', ['8.8.8.8']), ('example.com', ['8.8.8.8']),
                          ('a.example.com', ['127.0.0.1'])]:
            with self.assertRaises(ValueError):
                dns.provision(api, 'example.com', [name], ips)
        self.assertFalse(api.writes)

    def test_pagination_includes_conflict_on_second_page(self):
        api = dns.Cloudflare('x' * 40)
        with patch.object(api, 'request', side_effect=[
                {'result': [{'type': 'TXT'}], 'result_info': {'total_pages': 2}},
                {'result': [{'type': 'CNAME'}], 'result_info': {'total_pages': 2}}]) as call:
            result = api.records('a' * 32, name='a.example.com')
        self.assertEqual(len(result), 2)
        self.assertIn('page=2', call.call_args.args[1])
        self.assertIn('name.exact=a.example.com', call.call_args.args[1])

    def test_missing_pagination_fails_closed(self):
        api = dns.Cloudflare('x' * 40)
        with patch.object(api, 'request', return_value={'result': []}), self.assertRaises(RuntimeError):
            api.records('a' * 32, name='a.example.com')

    def test_api_token_is_header_only_and_error_body_never_reported(self):
        token = 'secret' * 8
        api = dns.Cloudflare(token)
        error = urllib.error.HTTPError('https://api.cloudflare.com', 403, token, {}, io.BytesIO(token.encode()))
        with patch.object(api.opener, 'open', side_effect=error) as request:
            with self.assertRaises(RuntimeError) as caught:
                api.request('GET', '/zones')
        self.assertNotIn(token, str(caught.exception))
        req = request.call_args.args[0]
        self.assertEqual(req.get_header('Authorization'), 'Bearer ' + token)
        self.assertNotIn(token, req.full_url)

    def test_http_200_success_false_is_failure(self):
        api = dns.Cloudflare('x' * 40)
        with patch.object(api.opener, 'open', return_value=io.BytesIO(b'{"success":false}')):
            with self.assertRaises(RuntimeError):
                api.request('GET', '/zones')

    def test_no_token_prompt_without_terminal(self):
        with patch.object(dns.sys.stdin, 'isatty', return_value=False), \
                patch.object(dns.getpass, 'getpass') as prompt:
            with self.assertRaises(RuntimeError):
                dns.ensure('example.com', ['hy.example.com'], ['8.8.8.8'])
            prompt.assert_not_called()

    def test_dns_wait_requires_local_and_public_exact_match(self):
        with patch.object(dns, 'public_addresses', return_value={'8.8.8.8'}), \
                patch.object(dns, 'local_addresses', return_value={'8.8.8.8'}):
            dns.wait_dns(['hy.example.com'], ['8.8.8.8'], timeout=1)
        with patch.object(dns, 'public_addresses', return_value={'8.8.8.8', '2606:4700::1111'}), \
                patch.object(dns, 'local_addresses', return_value={'8.8.8.8'}), \
                patch.object(dns.time, 'monotonic', side_effect=[0, 0, 0, 2, 2]), \
                patch.object(dns.time, 'sleep'):
            with self.assertRaises(RuntimeError):
                dns.wait_dns(['hy.example.com'], ['8.8.8.8'], timeout=1)

    def test_new_base_install_template_preserves_external_sni(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch('builtins.input', side_effect=['1 2 3', 'example.com', 'vps1', '',
                                                   '8.8.8.8', 'test@example.com']), \
                patch.object(base, 'ask_domain', side_effect=['mask.example.org', 'target.example.org']), \
                patch.object(base.getpass, 'getpass', return_value=''):
            target = Path(tmp) / 'state.json'
            base.collect(target, cloudflare=True)
            s = base.read_json(target)
        self.assertEqual(s['mtg_sni'], 'mask.example.org')
        self.assertEqual(s['reality_sni'], 'target.example.org')
        self.assertEqual(s['mtg_domain'], 'tg-vps1.example.com')
        self.assertEqual(s['hy_domain'], 'hy-vps1.example.com')
        self.assertNotIn('token', json.dumps(s))

    def test_extra_template_preserves_existing_domains_and_credentials(self):
        old = {'schema': 1, 'services': {'naive': {'domain': 'custom.example.com',
                'user': 'a' * 24, 'password': 'b' * 32}}}
        result = extras.collect(old, ['naive', 'xhttp'], state(), {'zone': 'example.com', 'prefix': 'vps1'})
        self.assertEqual(result['services']['naive'], old['services']['naive'])
        self.assertEqual(result['services']['xhttp']['domain'], 'xhttp-vps1.example.com')


if __name__ == '__main__':
    unittest.main()

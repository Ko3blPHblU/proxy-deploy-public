"""Regression tests for config reloads, rollback safety and sanitized evidence."""
import json
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import proxy_config as config
from test_proxy_config import state


class RegressionTests(unittest.TestCase):
    def setUp(self):
        config.SECRETS.clear()
        config.DIAGNOSTIC_PATH = None

    def tearDown(self):
        config.SECRETS.clear()
        config.DIAGNOSTIC_PATH = None

    def test_config_change_changes_only_affected_service_definition(self):
        images = {name: value.split(':')[0] + '@sha256:' + 'a' * 64
                  for name, value in config.IMAGES.items()}
        s = state()
        with tempfile.TemporaryDirectory() as tmp:
            config.generate(s, images, tmp)
            before = config.read_json(Path(tmp) / 'compose.json')
            config.generate(s, images, tmp)
            self.assertEqual(before, config.read_json(Path(tmp) / 'compose.json'))
            s['hy_password'] = 'changed-password-123456789'
            config.generate(s, images, tmp)
            after = config.read_json(Path(tmp) / 'compose.json')
        self.assertNotEqual(before['services']['hysteria'], after['services']['hysteria'])
        for name in ('xui', 'mtg'):
            self.assertEqual(before['services'][name], after['services'][name])

    def test_mtg_secret_change_changes_container_definition(self):
        images = {name: value.split(':')[0] + '@sha256:' + 'a' * 64
                  for name, value in config.IMAGES.items()}
        s = state()
        with tempfile.TemporaryDirectory() as tmp:
            config.generate(s, images, tmp)
            before = config.read_json(Path(tmp) / 'compose.json')
            s['mtg_secret'] = 'ee' + 'cd' * 16 + s['mtg_sni'].encode().hex()
            config.generate(s, images, tmp)
            after = config.read_json(Path(tmp) / 'compose.json')
        self.assertNotEqual(before['services']['mtg'], after['services']['mtg'])
        self.assertEqual(before['services']['hysteria'], after['services']['hysteria'])

    def make_db(self, path, value):
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE settings (value TEXT)')
            db.execute('INSERT INTO settings VALUES (?)', (value,))

    def test_rollback_refuses_running_database_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'db' / 'x-ui.db'
            target.parent.mkdir()
            backup = Path(tmp) / 'backup.db'
            self.make_db(target, 'live')
            self.make_db(backup, 'old')
            wal = Path(str(target) + '-wal')
            wal.write_bytes(b'live-wal-evidence')
            before = target.read_bytes()
            with patch.object(config, 'docker_output', side_effect=[
                    'container\n', json.dumps([{'Mounts': [{'Source': str(target.parent)}]}])]):
                with self.assertRaises(RuntimeError):
                    config.restore_database(backup, target)
            self.assertEqual(before, target.read_bytes())
            self.assertEqual(wal.read_bytes(), b'live-wal-evidence')

    def test_docker_unavailable_blocks_database_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, backup = Path(tmp) / 'live.db', Path(tmp) / 'backup.db'
            self.make_db(target, 'live')
            self.make_db(backup, 'old')
            before = target.read_bytes()
            with patch.object(config, 'docker_output', side_effect=RuntimeError('offline')):
                with self.assertRaises(RuntimeError):
                    config.restore_database(backup, target)
            self.assertEqual(before, target.read_bytes())

    def test_corrupt_backup_never_replaces_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, backup = Path(tmp) / 'live.db', Path(tmp) / 'backup.db'
            self.make_db(target, 'live')
            backup.write_bytes(b'not a sqlite database')
            before = target.read_bytes()
            with patch.object(config, 'database_idle'):
                with self.assertRaises(sqlite3.DatabaseError):
                    config.restore_database(backup, target)
            self.assertEqual(before, target.read_bytes())

    def test_successful_restore_preserves_displaced_database_and_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, backup = Path(tmp) / 'live.db', Path(tmp) / 'backup.db'
            self.make_db(target, 'live')
            self.make_db(backup, 'old')
            wal = Path(str(target) + '-wal')
            wal.write_bytes(b'old-wal')
            with patch.object(config, 'database_idle') as idle:
                config.restore_database(backup, target)
                self.assertEqual(idle.call_count, 2)
            with closing(sqlite3.connect(target)) as db:
                self.assertEqual(db.execute('SELECT value FROM settings').fetchone(), ('old',))
            recovery = list(Path(tmp).glob('before-restore-*'))
            self.assertEqual(len(recovery), 1)
            self.assertEqual((recovery[0] / 'live.db-wal').read_bytes(), b'old-wal')
            self.assertFalse(wal.exists())

    def test_failed_replacement_restores_original_db_and_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, backup = Path(tmp) / 'live.db', Path(tmp) / 'backup.db'
            self.make_db(target, 'live')
            self.make_db(backup, 'old')
            wal = Path(str(target) + '-wal')
            wal.write_bytes(b'live-wal')
            before = target.read_bytes()
            real_replace = Path.replace

            def fail_new_db(path, dest):
                if path.name.startswith('.restore-'):
                    raise OSError('simulated replacement error')
                return real_replace(path, dest)

            with patch.object(config, 'database_idle'), patch.object(Path, 'replace', fail_new_db):
                with self.assertRaises(OSError):
                    config.restore_database(backup, target)
            self.assertEqual(before, target.read_bytes())
            self.assertEqual(wal.read_bytes(), b'live-wal')

    def test_docker_error_is_logged_but_credentials_are_redacted(self):
        s = state()
        config.register_secrets(s)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / 'diagnostics.log'
            config.DIAGNOSTIC_PATH = log
            result = subprocess.CompletedProcess([], 42, 'stdout detail',
                'permission denied password=' + s['panel_password'] + '\n' + s['hy_password'])
            with patch.object(config.subprocess, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    config.docker_output(['secret-arguments-not-to-be-logged'])
            text = log.read_text(encoding='utf-8')
            self.assertIn('exit=42', text)
            self.assertIn('permission denied', text)
            self.assertNotIn(s['panel_password'], text)
            self.assertNotIn(s['hy_password'], text)
            self.assertNotIn('secret-arguments', text)

    def test_escaped_secrets_and_bearer_tokens_are_redacted(self):
        s = state()
        config.register_secrets(s)
        text = config.redact(json.dumps(s) + '\nAuthorization: Bearer UNREGISTERED-TOKEN')
        self.assertNotIn(json.dumps(s['hy_password'])[1:-1], text)
        self.assertNotIn(s['panel_password'], text)
        self.assertNotIn('UNREGISTERED-TOKEN', text)

    def test_failed_probe_collects_evidence_before_removal(self):
        order = []
        cid = 'a' * 64

        def docker(args):
            order.append(args[0])
            return cid if args[0] == 'run' else ''

        with tempfile.TemporaryDirectory() as tmp, patch.object(config.socket, 'socket'), \
                patch.object(config, 'tcp_probe'), patch.object(config, 'docker_output', docker), \
                patch.object(config, 'capture_container', side_effect=lambda *_: order.append('capture')), \
                patch.object(config.subprocess, 'run', return_value=subprocess.CompletedProcess([], 7, b'', b'failed')):
            with self.assertRaises(RuntimeError):
                config.client_probe(state(), config.IMAGES, 'hysteria', Path(tmp) / 'probe.json')
        self.assertEqual(order, ['run', 'capture', 'rm'])


class BashSafetyTests(unittest.TestCase):
    """Execute only extracted functions, with mocked commands; never run the installer."""
    def bash(self, script):
        if os.name == 'nt':
            self.skipTest('POSIX shell regression tests run on Ubuntu in CI')
        binary = shutil.which('bash')
        if not binary or not Path(binary).exists():
            self.skipTest('Bash not installed')
        return subprocess.run([binary, '--noprofile', '--norc', '-c', script],
                              capture_output=True, text=True, timeout=30)

    def function(self, name):
        source = Path(__file__).with_name('deploy-proxy.sh').read_text(encoding='utf-8')
        start = source.index(name + '() {')
        end = source.index('\n}\n', start) + 3
        return source[start:end]

    def test_failed_compose_stop_prevents_every_restore_command(self):
        script = self.function('rollback_containers') + '''
LOG=/dev/null
PREVIOUS_COMPOSE=1
EVENTS=()
warn() { :; }
compose() { EVENTS+=("compose-$1"); return 1; }
python3() { EVENTS+=(UNEXPECTED-python); }
cp() { EVENTS+=(UNEXPECTED-copy); }
rollback_containers
[[ $? == 1 ]] || exit 99
printf '%s\n' "${EVENTS[@]}"
'''
        result = self.bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'compose-down')

    def test_failed_database_restore_prevents_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'x-ui.db').touch()
            # Paths are test-controlled; no quotes or shell metacharacters.
            script = self.function('rollback_containers') + f'\nBACKUP="{Path(tmp).as_posix()}"\n' + '''
LOG=/dev/null
HELPER=mock
PREVIOUS_COMPOSE=1
EVENTS=()
warn() { :; }
compose() { EVENTS+=("compose-$1"); return 0; }
python3() { EVENTS+=(restore-refused); return 1; }
cp() { EVENTS+=(UNEXPECTED-copy); }
rollback_containers
[[ $? == 1 ]] || exit 99
printf '%s\n' "${EVENTS[@]}"
'''
            result = self.bash(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['compose-down', 'restore-refused'])


if __name__ == '__main__':
    unittest.main()

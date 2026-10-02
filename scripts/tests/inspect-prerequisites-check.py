"""Offline contract checks for the root diagnostic; no real DNF or host changes."""
import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'deploy/native/inspect-prerequisites.sh'
SOURCE = SCRIPT.read_text()
REPORT = SOURCE.split("<<'DNF_REPORT'\n", 1)[1].split('\nDNF_REPORT\n', 1)[0]


class Inspector(unittest.TestCase):
    def report(self, kind, out='', err='', code=0):
        with tempfile.TemporaryDirectory() as directory:
            out_path, err_path = (Path(directory) / name for name in ('stdout', 'stderr'))
            out_path.write_bytes(out.encode('utf-8'))
            err_path.write_bytes(err.encode('utf-8'))
            result = subprocess.run([sys.executable, '-I', '-B', '-c', REPORT, kind, str(code), str(out_path), str(err_path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
            self.assertEqual(result.stderr, '')
            return result.stdout

    def shell(self, commands, *args):
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', 'source "$1"\n' + commands, 'test', str(SCRIPT)] + list(args),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=20)

    def test_syntax_and_embedded_python36_grammar(self):
        subprocess.run(['/bin/bash', '-n', str(SCRIPT)], check=True)
        if sys.version_info >= (3, 8):
            ast.parse(REPORT, feature_version=(3, 6))
        else:
            ast.parse(REPORT)

    def test_sourcing_never_inspects_host(self):
        result = self.shell('')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_invalid_arguments_do_not_invoke_queries(self):
        result = self.shell('cached_dnf() { echo MUST_NOT_RUN; }; main --install')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('MUST_NOT_RUN', result.stdout)

    def test_dnf_argv_preserves_system_resolution_and_has_only_fixed_read_commands(self):
        result = self.shell('''
scratch=/tmp/fake-private-scratch
run() { printf 'GENERAL'; printf '|%s' "$@"; printf '\\n'; }
run_dnf() { printf 'DNF'; printf '|%s' "$@"; printf '\\n'; }
cached_dnf
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [row.split('|') for row in result.stdout.splitlines()]
        self.assertEqual(rows[0], ['GENERAL', 'cached-package-manager', 'rpm', '-q', 'dnf', 'python3-dnf', 'libdnf'])
        self.assertEqual(len(rows), 5)
        commands = []
        for row in rows[1:]:
            self.assertEqual(row[3:9], ['dnf', '-C', '--noplugins', '--setopt=gpgkey_dns_verification=False', '--setopt=persistdir=/tmp/fake-private-scratch', '--setopt=logdir=/tmp/fake-private-scratch'])
            commands.append(row[9])
            for argument in row:
                self.assertFalse(argument.startswith(('--config', '--releasever', '--setopt=reposdir', '--setopt=varsdir', '--setopt=cachedir', '--setopt=module_platform_id')))
                self.assertNotIn(argument, ('install', 'upgrade', 'makecache', '--refresh', '--allowerasing', 'download'))
        self.assertEqual(commands, ['repolist', 'list', 'module', 'repoquery'])
        self.assertIn('--disable-modular-filtering', rows[-1])

    def test_dnf_only_does_not_repeat_general_host_facts(self):
        # main's root guard is retained in production. Test only its control flow with a
        # synthetic root guard and mocked functions; never use privileged execution.
        main = SOURCE.split('main() {\n', 1)[1].split('\nif [[ ${BASH_SOURCE', 1)[0]
        main = main.replace('[[ $EUID = 0 && ', '[[ 0 = 0 && ', 1)
        result = self.shell('''
run() { echo "UNEXPECTED $*"; }
cached_dnf() { echo ONLY_DNF; }
mktemp() { printf /tmp/aifinance-test-no-created-directory; }
trap() { :; }
main() {
''' + main + '\nmain --dnf-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ONLY_DNF', result.stdout)
        self.assertNotIn('UNEXPECTED', result.stdout)

    def test_known_config_failure_is_useful_without_raw_stderr(self):
        result = self.report('repositories', err='Config error: Config file "/dev/null" does not exist\nsecret=DO_NOT_DISCLOSE\n', code=1)
        self.assertIn('config_path_not_regular,config_error', result)
        self.assertIn('exit=1', result)
        self.assertNotIn('DO_NOT_DISCLOSE', result)
        self.assertNotIn('/dev/null', result)

    def test_other_dnf_failures_are_classified_and_never_echo_config_or_urls(self):
        cases = [
            ('Error: Cache-only enabled but no cache for private-repo', 'cache_unavailable'),
            ('Unable to detect release version (use --releasever)', 'releasever_unknown'),
            ('No valid Platform ID detected', 'module_platform_unknown'),
            ('nothing provides module(platform:el8)', 'module_platform_unknown'),
            ('dnf: error: unrecognized arguments: --unknown', 'unsupported_command_or_option'),
            ('Error: No such command: repoquery', 'unsupported_command_or_option'),
            ('Permission denied: /private/secret', 'permission_denied'),
            ('Error: No matching Modules to list', 'no_matching_packages_or_modules'),
            ('There are no enabled repositories', 'repository_unavailable'),
            ('surprising private exception', 'unclassified_error_withheld'),
        ]
        for message, expected in cases:
            with self.subTest(message=message):
                result = self.report('packages', err=message + '\nhttps://user:DO_NOT_DISCLOSE@example.invalid/?token=DO_NOT_DISCLOSE\n', code=1)
                self.assertIn(expected, result)
                self.assertNotIn('DO_NOT_DISCLOSE', result)
                self.assertNotIn('example.invalid', result)
                self.assertNotIn('/private/', result)

    def test_repositories_return_ids_without_names_or_preheader_noise(self):
        result = self.report('repositories', out='DO_NOT_DISCLOSE unexpected preamble\nrepo id         repo name\nalinux3-base    https://user:DO_NOT_DISCLOSE@example.invalid\nepel           private organization name\npgdg17         PostgreSQL 17\nError: private_failure\n')
        for repo in ('alinux3-base', 'epel', 'pgdg17'):
            self.assertIn('repository_id=' + repo, result)
        for secret in ('DO_NOT_DISCLOSE', 'example.invalid', 'organization', 'private_failure', 'repository_id=Error'):
            self.assertNotIn(secret, result)

    def test_package_and_list_records_are_structured(self):
        for kind, out in [('packages', 'postgresql17-server|17.6-1PGDG.rhel8|x86_64|pgdg17\n'),
                          ('list', 'Available Packages\npostgresql17-server.x86_64 17.6-1PGDG.rhel8 pgdg17\n')]:
            result = self.report(kind, out=out + 'https://user:DO_NOT_DISCLOSE@example.invalid\n')
            self.assertIn('postgresql17-server|17.6-1PGDG.rhel8|x86_64|pgdg17', result)
            self.assertNotIn('DO_NOT_DISCLOSE', result)
            self.assertIn('exit=0', result)
        self.assertIn('postgresql|10.17-1.al8|x86_64|alinux3-base', self.report('packages', out='postgresql|10.17-1.al8|x86_64|alinux3-base\n'))

    def test_modules_expose_only_stream_and_state_flags(self):
        result = self.report('modules', out='private repo name\npostgresql 10 [d][e] client, server [d] private description\npostgresql 13 [e] client, server [d] private description\npostgresql 12 client, server private description\n')
        self.assertIn('postgresql|stream=10|flags=d,e', result)
        self.assertIn('postgresql|stream=13|flags=e', result)
        self.assertIn('postgresql|stream=12|flags=none', result)
        self.assertNotIn('private', result)

    def test_error_status_empty_results_and_truncation_remain_unknown(self):
        result = self.report('packages', code=124)
        self.assertIn('exit=124', result)
        self.assertIn('timeout_or_killed', result)
        result = self.report('packages', out='x' * 8193, err='y' * 8193, code=141)
        self.assertIn('stdout_truncated=yes', result)
        self.assertIn('stderr_truncated=yes', result)
        self.assertLess(len(result), 512)
        self.assertNotIn('x' * 32, result)
        self.assertIn('missing records mean UNKNOWN, not proven absence', SOURCE)

    def test_real_capture_is_bounded_clean_environment_and_waits_for_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            # This fake command replaces DNF, and does not read host package/config data.
            emitter = Path(directory) / 'emitter'
            emitter.write_text('#!/bin/sh\n[ -z "${AIFINANCE_SECRET+x}" ] || exit 99\nprintf "%s\\n" "postgresql|10.17-1.al8|x86_64|alinux3-base"\nprintf "%s\\n" "Config error: Config file \\\"/dev/null\\\" does not exist" >&2\nexit 1\n')
            emitter.chmod(0o700)
            result = self.shell('scratch="$2"; export AIFINANCE_SECRET=DO_NOT_DISCLOSE; run_dnf fake packages "$3"', directory, str(emitter))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('config_path_not_regular', result.stdout)
            self.assertIn('exit=1', result.stdout)
            self.assertIn('postgresql|10.17-1.al8|x86_64|alinux3-base', result.stdout)
            self.assertNotIn('DO_NOT_DISCLOSE', result.stdout + result.stderr)
            emitter.write_text('#!/bin/sh\nhead -c 100000 /dev/zero >&2\nhead -c 100000 /dev/zero\n')
            result = self.shell('scratch="$2"; run_dnf fake packages "$3"', directory, str(emitter))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLessEqual((Path(directory) / 'query.err').stat().st_size, 8193)
            self.assertLessEqual((Path(directory) / 'query.out').stat().st_size, 8193)
            self.assertIn('stderr_truncated=yes', result.stdout)
            self.assertLess(len(result.stdout), 512)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3
"""First-only, separately approved preview database/env provisioning (Python 3.6.8+).

Run a reviewed root-owned copy at /root/aifinance-native-inputs with python3 -I -B.
Default check is read-only; apply requires the administrator's interactive terminal.
Never run release code, repair partial installs, enable boot startup, or mark ready.
"""
import argparse
import getpass
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
import warnings

SOURCE = Path('/root/aifinance-native-inputs')
PG = Path('/usr/pgsql-17')
DATA = Path('/var/lib/pgsql/aifinance-preview')
CONFIG = Path('/etc/aifinance-preview-db')
SOCKET = Path('/run/aifinance-preview-db')
ENV_FILE = Path('/etc/aifinance-preview.env')
UNIT_NAME = 'aifinance-preview-db.service'
UNIT = Path('/etc/systemd/system') / UNIT_NAME
SYSTEMCTL = '/usr/bin/systemctl'
PG_UID = PG_GID = 26
PORT = 55432
ENV = {'PATH': '/usr/pgsql-17/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'HOME': '/', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}


def protected(path, directory=False):
    """Strict, root-owned ancestors; no symlinks or writable code/config paths."""
    for node in (path,) + tuple(path.parents):
        st = node.lstat()
        kind = stat.S_ISDIR if directory or node != path else stat.S_ISREG
        if not kind(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('unprotected_path')


def absent(path):
    if path.exists() or path.is_symlink():
        raise ValueError('existing_path_requires_manual_review')


def as_postgres():
    # Only used in this single-threaded trusted administrator process.
    os.setgroups([])
    os.setgid(PG_GID)
    os.setuid(PG_UID)
    os.umask(0o077)


def run(args, postgres=False, data=None, capture=False, timeout=30):
    # Never inherit LD_*, PG*, PYTHON*, provider keys, startup files, or passwords.
    process = subprocess.Popen(args, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=ENV, cwd='/', shell=False,
                               start_new_session=True, preexec_fn=as_postgres if postgres else None)
    try:
        output, _ = process.communicate(input=data if data is not None else b'', timeout=timeout)
    except BaseException:
        # initdb can spawn bootstrap backends. Kill/reap the entire new process
        # group on timeout/interruption, not merely the initdb parent process.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    if process.returncode != 0:
        raise ValueError('fixed_command_failed')
    return output.decode('utf-8').strip() if capture else None


def accounts():
    pg, group = pwd.getpwnam('postgres'), grp.getgrnam('postgres')
    app, app_group = pwd.getpwnam('aifinance'), grp.getgrnam('aifinance')
    if (pg.pw_uid != PG_UID or pg.pw_gid != PG_GID or group.gr_gid != PG_GID or
            pwd.getpwuid(PG_UID).pw_name != 'postgres' or grp.getgrgid(PG_GID).gr_name != 'postgres' or
            app.pw_uid in (0, PG_UID) or app.pw_gid != app_group.gr_gid or app.pw_gid in (0, PG_GID)):
        raise ValueError('expected_existing_service_accounts_required')
    return app.pw_gid


def preflight(script_digest, unit_digest):
    if os.getuid() != 0 or os.geteuid() != 0 or os.getegid() != 0:
        raise ValueError('trusted_root_administrator_required')
    if sys.version_info < (3, 6, 8):
        raise ValueError('python_3_6_8_required')
    if Path(__file__).absolute() != SOURCE / 'provision-database.py':
        raise ValueError('fixed_reviewed_source_location_required')
    for name, digest in (('provision-database.py', script_digest), (UNIT_NAME, unit_digest)):
        path = SOURCE / name
        protected(path)
        if not re.fullmatch(r'[0-9a-f]{64}', digest or '') or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('reviewed_source_digest_mismatch')
    gid = accounts()
    for parent in (CONFIG.parent, UNIT.parent, SOCKET.parent):
        protected(parent, directory=True)
    # PGDG owns /var/lib/pgsql as postgres on some builds. Never chmod/chown it.
    protected(DATA.parent.parent, directory=True)
    st = DATA.parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, PG_UID) or st.st_gid not in (0, PG_GID) or st.st_mode & 0o022:
        raise ValueError('unexpected_pgdg_data_parent')
    for path in (DATA, CONFIG, SOCKET, ENV_FILE, UNIT,
                 Path('/run/systemd/system') / UNIT_NAME, UNIT.parent / (UNIT_NAME + '.d')):
        absent(path)
    for tool in ('postgres', 'initdb', 'psql'):
        protected(PG / 'bin' / tool)
        version = run([str(PG / 'bin' / tool), '--version'], postgres=True, capture=True)
        if not re.fullmatch(tool + r' \(PostgreSQL\) 17\.11', version):
            raise ValueError('reviewed_postgresql_17_11_required')
    protected(PG / 'lib', directory=True)
    protected(PG / 'share', directory=True)
    protected(PG / 'lib/pg_trgm.so')
    protected(PG / 'share/extension/pg_trgm.control')
    protected(Path(SYSTEMCTL))
    if run([SYSTEMCTL, 'show', UNIT_NAME, '-p', 'LoadState', '--value'], capture=True) != 'not-found':
        raise ValueError('existing_or_unverifiable_database_unit')
    # A read-only bind check; never stop a listener or touch any other service.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', PORT))
    fs = os.statvfs(str(DATA.parent))
    if fs.f_bavail * fs.f_frsize < 1024 ** 3:
        raise ValueError('database_disk_reserve_required')
    return gid


def configuration():
    return ("data_directory = '%s'\nhba_file = '%s/pg_hba.conf'\nident_file = '%s/pg_ident.conf'\n"
            "listen_addresses = '127.0.0.1'\nport = 55432\n"
            "unix_socket_directories = '%s'\nunix_socket_permissions = 0700\n"
            "password_encryption = 'scram-sha-256'\n"
            "max_connections = 12\nsuperuser_reserved_connections = 3\n"
            "shared_buffers = '32MB'\nwork_mem = '1MB'\nmaintenance_work_mem = '16MB'\n"
            "autovacuum_max_workers = 1\nautovacuum_work_mem = '8MB'\n"
            "wal_buffers = '1MB'\nmin_wal_size = '64MB'\nmax_wal_size = '128MB'\n"
            "max_worker_processes = 0\nmax_parallel_workers = 0\n"
            "max_parallel_workers_per_gather = 0\ntemp_file_limit = '64MB'\n"
            "huge_pages = off\njit = off\nssl = off\n"
            "log_statement = 'none'\nlog_min_duration_statement = -1\n"
            "log_min_duration_sample = -1\nlog_transaction_sample_rate = 0\n"
            "log_min_error_statement = 'panic'\nlog_parameter_max_length = 0\n"
            "log_parameter_max_length_on_error = 0\nlogging_collector = off\nlog_destination = 'stderr'\n"
            % (DATA, CONFIG, CONFIG, SOCKET))


HBA = ('local all postgres peer\n'
       'local all all reject\n'
       'host aifinance_preview aifinance_preview 127.0.0.1/32 scram-sha-256\n'
       'host all all 0.0.0.0/0 reject\n'
       'host all all ::0/0 reject\n')


def administrator_password():
    # getpass must not fall back to echoed input or redirected stdin.
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError('interactive_administrator_tty_required')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass('New preview administrator password (hidden): ')
        repeated = getpass.getpass('Repeat preview administrator password (hidden): ')
    if (password != repeated or not 12 <= len(password) <= 256 or
            any(ord(c) < 33 or ord(c) > 126 for c in password)):
        raise ValueError('matching_12_to_256_printable_nonspace_characters_required')
    return password


def environment(admin, database, session, image):
    # Generated hex makes DATABASE_URL and the one-line env parser unambiguous.
    if not all(re.fullmatch(r'[0-9a-f]{64}', value) for value in (database, session, image)):
        raise ValueError('expected_generated_hex_secrets')
    if not 12 <= len(admin) <= 256 or any(ord(c) < 33 or ord(c) > 126 for c in admin):
        raise ValueError('invalid_administrator_password')
    return ('DATABASE_URL=postgres://aifinance_preview:' + database + '@127.0.0.1:55432/aifinance_preview\n'
            'SITE_URL=http://127.0.0.1:3100\nADMIN_PASSWORD=' + admin + '\nSESSION_SECRET=' + session +
            '\nIMG_PROXY_SIGN_SECRET=' + image + '\n')

def write_new(path, data, mode, gid):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        os.fchown(out.fileno(), 0, gid)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
        os.fchmod(out.fileno(), mode)


def psql(sql, database='postgres', capture=False):
    return run([str(PG / 'bin/psql'), '--no-psqlrc', '--no-password', '--quiet', '--tuples-only',
                '--no-align', '--set=ON_ERROR_STOP=1', '--host=' + str(SOCKET), '--port=55432',
                '--username=postgres', '--dbname=' + database], postgres=True,
               data=sql.encode('ascii'), capture=capture, timeout=10)


def initialize(app_gid, admin):
    """No cleanup on failure. Only stop this invocation's newly installed unit."""
    for path in (CONFIG, DATA, ENV_FILE, UNIT, SOCKET):
        absent(path)
    database, session, image = (secrets.token_hex(32) for _ in range(3))
    env_text = environment(admin, database, session, image)
    new_unit = False
    try:
        CONFIG.mkdir(mode=0o700)  # Exclusive first durable marker; retained on failure.
        os.chown(str(CONFIG), 0, PG_GID)
        for name, data in (('postgresql.conf', configuration()), ('pg_hba.conf', HBA), ('pg_ident.conf', '')):
            write_new(CONFIG / name, data.encode('ascii'), 0o640, PG_GID)
        CONFIG.chmod(0o750)
        # Do not write/chown files inside a postgres-writable directory as root.
        # Open the fresh directory without following links, and chown only its fd.
        DATA.mkdir(mode=0o700)
        fd = os.open(str(DATA), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchown(fd, PG_UID, PG_GID)
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        run([str(PG / 'bin/initdb'), '--pgdata=' + str(DATA), '--username=postgres',
             '--encoding=UTF8', '--locale=C', '--auth-local=peer', '--auth-host=scram-sha-256',
             '--no-clean', '--no-instructions', '--set=shared_buffers=32MB', '--set=max_connections=12'],
            postgres=True, timeout=180)
        write_new(ENV_FILE, env_text.encode('ascii'), 0o640, app_gid)
        write_new(UNIT, (SOURCE / UNIT_NAME).read_bytes(), 0o644, 0)
        new_unit = True
        run([SYSTEMCTL, 'daemon-reload'])
        if (run([SYSTEMCTL, 'show', UNIT_NAME, '-p', 'FragmentPath', '--value'], capture=True) != str(UNIT) or
                run([SYSTEMCTL, 'show', UNIT_NAME, '-p', 'DropInPaths', '--value'], capture=True)):
            raise ValueError('unexpected_unit_fragment_or_overrides')
        run([SYSTEMCTL, 'start', UNIT_NAME])
        # Type=simple start is not readiness. Probe only the dedicated peer socket.
        for attempt in range(30):
            try:
                if psql('SELECT 1;\n', capture=True) == '1':
                    break
            except (ValueError, subprocess.TimeoutExpired):
                pass
            if attempt == 29:
                raise ValueError('dedicated_database_not_ready')
            time.sleep(1)
        # Input goes only through a pipe. No credentials in argv/env, psql output,
        # statement/error/duration logs, history, or exceptions printed by this CLI.
        psql("CREATE ROLE aifinance_preview LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
             "NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 6 PASSWORD '" + database + "';\n"
             "CREATE DATABASE aifinance_preview OWNER aifinance_preview;\n"
             "REVOKE ALL ON DATABASE aifinance_preview FROM PUBLIC;\n")
        psql('CREATE EXTENSION pg_trgm;\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\n', 'aifinance_preview')
        if psql("SELECT current_setting('listen_addresses') = '127.0.0.1' "
                "AND current_setting('port') = '55432' "
                "AND current_setting('password_encryption') = 'scram-sha-256' "
                "AND EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_trgm') "
                "AND EXISTS (SELECT 1 FROM pg_authid WHERE rolname='aifinance_preview' "
                "AND rolpassword LIKE 'SCRAM-SHA-256$%' AND NOT rolsuper AND NOT rolcreaterole "
                "AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls);\n",
                'aifinance_preview', capture=True) != 't':
            raise ValueError('database_configuration_verification_failed')
        # Verify the actual application SCRAM route. psql reads the connection
        # URI from stdin, never process arguments or an inherited password env.
        if psql('\\connect "postgresql://aifinance_preview:' + database +
                '@127.0.0.1:55432/aifinance_preview"\n'
                "SELECT current_user = 'aifinance_preview' "
                "AND current_database() = 'aifinance_preview' "
                "AND similarity('finance', 'finance') = 1;\n", capture=True) != 't':
            raise ValueError('application_scram_route_verification_failed')
    except BaseException:
        if new_unit:
            # A second hangup/Ctrl-C must not bypass the bounded stop attempt.
            handlers = [(sig, signal.signal(sig, signal.SIG_IGN))
                        for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)]
            try:
                run([SYSTEMCTL, 'stop', UNIT_NAME], timeout=70)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                raise ValueError('new_database_stop_failed_manual_intervention_required')
            finally:
                for sig, handler in handlers:
                    signal.signal(sig, handler)
        raise


def interrupted(signum, frame):
    # Route terminal hangups and termination through process-group/unit cleanup.
    raise InterruptedError('administrator_session_interrupted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'check', 'apply'), nargs='?', default='check')
    parser.add_argument('--script-sha256')
    parser.add_argument('--unit-sha256')
    args = parser.parse_args(argv)
    if args.command == 'plan':
        print(json.dumps({'writes': [str(DATA), str(CONFIG), str(ENV_FILE), str(UNIT), str(SOCKET)],
                          'unit_started_not_enabled': UNIT_NAME, 'postgres_uid_gid': 26,
                          'port': PORT, 'requires_explicit_approval': True, 'ready_for_deploy': False}, sort_keys=True))
        return 0
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    if args.command == 'apply':
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGHUP, interrupted)
    app_gid = preflight(args.script_sha256, args.unit_sha256)
    if args.command == 'apply':
        admin = administrator_password()
        # Recheck before first write after time spent at the interactive prompt.
        if preflight(args.script_sha256, args.unit_sha256) != app_gid:
            raise ValueError('service_account_changed')
        initialize(app_gid, admin)
    print(json.dumps({'status': 'database_env_created' if args.command == 'apply' else 'check_only',
                      'changed': args.command == 'apply', 'ready_for_deploy': False,
                      'schema_migrated': False, 'boot_enabled': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, EOFError, UnicodeError, subprocess.SubprocessError,
            getpass.GetPassWarning, KeyboardInterrupt):
        # No exception text, command output, SQL, environment contents, or secrets.
        print(json.dumps({'status': 'failed', 'ready_for_deploy': False,
                          'action': 'verify_new_db_unit_stopped_then_inspect_preserved_paths_no_automatic_retry'}))
        sys.exit(1)

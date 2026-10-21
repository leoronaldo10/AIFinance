"""Root-only, no-argument, one-shot exporter. Never starts collection or alters DB."""
import os
import pwd
import socket
import stat
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_common import Refused, need, loads, decode, encode, sha256
from cloud_io import region, instance_credentials, object_request

ROOT = Path('/opt/aifinance-results-retry002')
CONFIG = Path('/etc/aifinance-results-retry002.json')
AUDIT = Path('/var/lib/aifinance-collect-once/retry-002')


def trusted(path, directory=False):
    st = path.lstat()
    need(st.st_uid == 0 and not st.st_mode & 0o022 and
         (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)), 'untrusted_local_file')
    for parent in path.parents:
        p = parent.lstat()
        need(stat.S_ISDIR(p.st_mode) and p.st_uid == 0 and not p.st_mode & 0o022, 'untrusted_parent')
    return st


def read_small(path, maximum=65536):
    trusted(path)
    with path.open('rb') as f:
        value = f.read(maximum + 1)
    need(len(value) <= maximum, 'local_file_size')
    return value


def bounds():
    low = trusted(AUDIT / 'before.dump')
    high = trusted(AUDIT / 'completed')
    need(read_small(AUDIT / 'completed', 256) == b'collector completed; never repeat\n', 'completion_marker')
    lower, upper = low.st_mtime_ns // 1000000000, high.st_mtime_ns // 1000000000
    need(low.st_size > 0 and 0 <= upper - lower <= 86400, 'audit_time_bounds')
    return lower, upper


def query(sql):
    account = pwd.getpwnam('postgres')
    need(account.pw_uid > 0 and account.pw_gid > 0, 'postgres_identity')
    endpoint = Path('/run/postgresql/.s.PGSQL.55432')
    for parent in endpoint.parents:
        st = parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid in (0, account.pw_uid) and
             not st.st_mode & 0o002 and (not st.st_mode & 0o020 or st.st_gid in (0, account.pw_gid)), 'socket_parent')
    st = endpoint.lstat()
    need(stat.S_ISSOCK(st.st_mode) and st.st_uid == account.pw_uid, 'postgres_socket')
    binary = Path('/usr/lib/postgresql/17/bin/psql')
    trusted(binary)
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
           'PGHOST': '/run/postgresql', 'PGPORT': '55432', 'PGDATABASE': 'aifinance_preview',
           'PGUSER': 'postgres', 'PGPASSFILE': '/dev/null/aifinance-readonly.pgpass',
           'PGCONNECT_TIMEOUT': '3', 'PGOPTIONS': '-c default_transaction_read_only=on -c statement_timeout=5000'}
    # SQL projects only bounded public columns from three rows. Unit additionally caps FS/memory/time.
    p = subprocess.run([str(binary), '-XwAtq', '-v', 'ON_ERROR_STOP=1', '-P', 'pager=off'],
                       input=sql, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12,
                       env=env, cwd='/', user=account.pw_uid, group=account.pw_gid,
                       extra_groups=[], umask=0o077)
    need(p.returncode == 0 and not p.stderr, 'fixed_readonly_query_failed')
    # RSS excerpts can contain harmless line breaks; normalize only public text fields.
    need(len(p.stdout) <= 131072, 'query_output_size')
    value = loads(p.stdout.strip())
    if isinstance(value, dict) and isinstance(value.get('articles'), list):
        for item in value['articles']:
            if isinstance(item, dict):
                for key in ('title', 'source_name', 'summary'):
                    if isinstance(item.get(key), str):
                        item[key] = ' '.join(item[key].split())
    return encode(value)


def main():
    need(len(sys.argv) == 1 and os.geteuid() == 0, 'root_no_arguments_required')
    need(Path(__file__).resolve().parent == ROOT, 'installed_path_required')
    need(socket.gethostname() == 'iZ2zedybs3fftu1d9vnx39Z', 'hostname_mismatch')
    # Verify every installed runtime byte before acquiring credentials or invoking psql.
    manifest = loads(read_small(ROOT / 'runtime-hashes.json'))
    need(set(manifest) == {'export_results.py', 'result_common.py', 'cloud_io.py', 'retry002.sql'}, 'runtime_manifest_scope')
    for name, expected in manifest.items():
        need(sha256(read_small(ROOT / name)) == expected, 'runtime_hash_mismatch')
    config = loads(read_small(CONFIG, 2048))
    need(set(config) == {'oss_region', 'internal_endpoint', 'instance_role_confirmed'} and
         config['instance_role_confirmed'] is True and type(config['internal_endpoint']) is bool, 'config_fields')
    area = region(config['oss_region'])
    need(not config['internal_endpoint'] or area == 'cn-beijing', 'internal_region_mismatch')
    lower, upper = bounds()
    sql = read_small(ROOT / 'retry002.sql').decode().replace('__LOWER_EPOCH__', str(lower)).replace('__UPPER_EPOCH__', str(upper))
    payload = query(sql.encode())
    creds = instance_credentials()  # conflict or unavailable => no PUT, no fallback credentials
    object_request('PUT', area, creds, payload, internal=config['internal_endpoint'])
    print('{"status":"uploaded_private_retry002","articles":3,"sha256":"' + sha256(payload) + '"}')


if __name__ == '__main__':
    try:
        main()
    except Refused as e:
        print('{"status":"refused","reason":"' + str(e) + '"}')
        sys.exit(1)
    except Exception:
        print('{"status":"refused","reason":"local_operation_failed_details_suppressed"}')
        sys.exit(1)

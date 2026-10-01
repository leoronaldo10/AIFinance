#!/usr/bin/python3
"""Preparation only unless --apply is explicitly passed by the server administrator.
Creates fresh accounts/access paths; never adopts existing installations or installs runtimes.
"""
import argparse
import base64
import grp
import os
from pathlib import Path
import pwd
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path('/opt/aifinance')
HOME = Path('/var/lib/aifinance-deploy')
SUDO = Path('/etc/sudoers.d/aifinance-preview')
SUDO_RULE = 'aifinance-deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart aifinance-preview-api.service aifinance-preview-web.service\n'
SCRIPTS = ('ssh-gateway.py', 'release.sh', 'run-preview.py')


def public_key(text):
    fields = text.strip().split()
    if len(text.strip().splitlines()) != 1 or len(fields) < 2 or fields[0] != 'ssh-ed25519':
        raise ValueError('Expected one plain Ed25519 public key, without authorized_keys options')
    raw = base64.b64decode(fields[1], validate=True)
    expected = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
    if len(raw) != len(expected) + 32 or not raw.startswith(expected):
        raise ValueError('Invalid Ed25519 public key encoding')
    return 'ssh-ed25519 ' + fields[1] + ' aifinance-actions'


def authorized_key(key):
    return 'restrict,command="/usr/bin/python3 -I /opt/aifinance/bin/ssh-gateway.py" ' + key + '\n'


def preflight(source):
    for parent in (ROOT.parent, HOME.parent, SUDO.parent):
        st = parent.stat()
        if parent.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError('Provisioning parent must be root-owned and not writable by other users')
    for path in (ROOT, HOME, SUDO, Path('/etc/aifinance-preview.env')):
        if path.exists() or path.is_symlink():
            raise ValueError('Existing AIFinance path detected; stop for manual reconciliation')
    for name in ('aifinance', 'aifinance-deploy'):
        try:
            pwd.getpwnam(name)
        except KeyError:
            pass
        else:
            raise ValueError('Existing account; will not modify it')
        try:
            grp.getgrnam(name)
        except KeyError:
            pass
        else:
            raise ValueError('Existing group; will not modify it')
    for role in ('api', 'web'):
        result = subprocess.run(['/usr/bin/systemctl', 'show', 'aifinance-preview-' + role + '.service', '-p', 'LoadState', '--value'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if result.returncode != 0 or result.stdout.strip() != 'not-found':
            raise ValueError('Existing or unverifiable AIFinance service; no changes made')
    for tool in ('useradd', 'visudo', 'sshd', 'nologin'):
        if not shutil.which(tool):
            raise ValueError('Required system tool missing: ' + tool)
    for name in SCRIPTS:
        p = source / name
        if not p.is_file() or p.is_symlink() or p.stat().st_uid != 0 or p.stat().st_mode & 0o022:
            raise ValueError('Reviewed access scripts must be regular local files')
    # Fail closed if sshd could accept caller-controlled interpreter variables or an alternate entry.
    settings = subprocess.check_output([shutil.which('sshd'), '-T', '-C', 'user=aifinance-deploy,host=localhost,addr=127.0.0.1'], universal_newlines=True)
    lines = settings.splitlines()
    if 'permituserenvironment no' not in lines or 'forcecommand none' not in lines:
        raise ValueError('Unexpected sshd per-user environment/command policy; inspect manually')
    if not any(x.startswith('authorizedkeysfile ') and '.ssh/authorized_keys' in x.split()[1:] for x in lines):
        raise ValueError('sshd does not use the expected authorized_keys path')
    for line in lines:
        if line.startswith('acceptenv ') and any(v not in ('LANG', 'LC_*') for v in line.split()[1:]):
            raise ValueError('Nonstandard AcceptEnv policy; inspect manually')


def provision(source, key):
    # Recheck paths before the first account operation, including direct/repeated invocations.
    if any(p.exists() or p.is_symlink() for p in (ROOT, HOME, SUDO)):
        raise ValueError("Existing access paths; no account operation performed")
    # Preflight prevents replacing existing users or paths. Abort on error; never auto-delete accounts.
    subprocess.run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', shutil.which('nologin'), 'aifinance'], check=True)
    subprocess.run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(HOME), '--shell', '/bin/sh', 'aifinance-deploy'], check=True)
    # useradd without a password creates a locked password entry; public-key login is host/PAM dependent.
    deploy = pwd.getpwnam('aifinance-deploy')
    app = pwd.getpwnam('aifinance')
    ROOT.mkdir(mode=0o755)
    for name in ('bin', 'shared'):
        (ROOT / name).mkdir(mode=0o755)
    for name, mode in (('state', 0o755), ('releases', 0o755), ('incoming', 0o700)):
        p = ROOT / name
        p.mkdir(mode=mode)
        os.chown(p, deploy.pw_uid, deploy.pw_gid)
    data = ROOT / 'shared/data'
    data.mkdir(mode=0o700)
    os.chown(data, app.pw_uid, app.pw_gid)
    for name in SCRIPTS:
        target = ROOT / 'bin' / name
        with target.open('xb') as out:
            out.write((source / name).read_bytes())
        target.chmod(0o755)
    HOME.mkdir(mode=0o755)
    (HOME / '.ssh').mkdir(mode=0o755)
    with (HOME / '.ssh/authorized_keys').open('x') as out:
        out.write(authorized_key(key))
    (HOME / '.ssh/authorized_keys').chmod(0o644)  # root-owned; deploy user cannot add keys or ssh rc files
    with SUDO.open('x') as out:
        out.write(SUDO_RULE)
    SUDO.chmod(0o440)
    subprocess.run([shutil.which('visudo'), '-c', '-f', str(SUDO)], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--public-key', required=True, type=Path)
    parser.add_argument('--apply', action='store_true', help='create fresh access accounts/paths after review')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run the reviewed preflight in the trusted server administrator terminal')
    os.umask(0o022)
    source = Path(__file__).resolve().parent
    key = public_key(args.public_key.read_text())
    preflight(source)
    with tempfile.NamedTemporaryFile(mode='w') as f:
        f.write(SUDO_RULE); f.flush()
        subprocess.run([shutil.which('visudo'), '-c', '-f', f.name], check=True)
    print('Plan: fresh aifinance/app and aifinance-deploy accounts; root-owned forced entry/key; restricted data paths; exact two-service restart sudo rule.')
    print('No runtime installation, unit installation, database changes, SSH configuration changes, key generation or service restart.')
    if not args.apply:
        print('CHECK ONLY: no persistent changes made. Review before using --apply.')
        return
    provision(source, key)
    print('ACCESS PREPARED: only verify is enabled until separate native-ready approval. No service started.')


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print('STOP: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, subprocess.CalledProcessError):
        print('STOP: preflight or provisioning failed. No existing installation was intentionally overwritten; inspect any partial new setup before retrying.', file=sys.stderr)
        sys.exit(1)

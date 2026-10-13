#!/usr/bin/env python3
"""Fixed API -> WS -> gateway orchestration; default live composition is locked.

Tests inject API and WebSocket factories, not a replacement orchestration path.
No real cloud credentials are loaded by import, tests, or the CLI.
"""
import contextlib
import fcntl
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

client = load('rebuilt_proxy_core', HERE / 'rebuilt-proxy.py')
evidence = load('rebuilt_provenance', HERE / 'rebuilt-provenance.py')
Stop = client.Stop
LIVE_EXECUTION_ENABLED = False
MAX_WIRE_BYTES = 1024 * 1024
APPROVAL = Path('/etc/aifinance-proxy-approval.json')


def denied(*args, **kwargs):
    raise Stop('live_not_authorized')


def close_bounded(close):
    """Cleanup has its own <=2s alarm even after the operation alarm has fired."""
    remaining,interval=signal.getitimer(signal.ITIMER_REAL)
    handler=signal.getsignal(signal.SIGALRM)
    started=time.monotonic()
    def expired(*_):raise Stop('cleanup_timeout_remote_session_unknown')
    signal.signal(signal.SIGALRM,expired)
    signal.setitimer(signal.ITIMER_REAL,min(remaining,2) if remaining else 2)
    try:close()
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,handler)
        if remaining:
            signal.setitimer(signal.ITIMER_REAL,max(.000001,remaining-(time.monotonic()-started)),interval)


@contextlib.contextmanager
def websocket_scope(context):
    ws=context.__enter__()
    try:yield ws
    finally:
        exception=sys.exc_info()
        close_bounded(lambda:context.__exit__(*exception))


def read_approval():
    # Local administrator approval, never a file selected by an operation argument.
    for path in (APPROVAL.parent, APPROVAL):
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise Stop('approval_not_trusted')
    fd = os.open(APPROVAL, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Stop('approval_not_trusted')
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise Stop('approval_limit')
    return json.loads(raw)


def checkout_revision():
    repo = HERE.parents[1]
    options = dict(cwd=repo, capture_output=True, check=True, timeout=10,
                   env={'PATH':'/usr/bin:/bin','LANG':'C','HOME':'/nonexistent'})
    if subprocess.run(['/usr/bin/git','status','--porcelain','--untracked-files=normal'], **options).stdout:
        raise Stop('checkout_not_clean')
    result = subprocess.run(['/usr/bin/git','rev-parse','HEAD'], **options).stdout.decode('ascii').strip()
    if not re.fullmatch(client.SHA, result):
        raise Stop('checkout_invalid')
    return result


class GitHubEvidence:
    """Fixed REST reads only, mandatory proxy/TLS, bounded JSON, no redirects/URLs."""
    def __init__(self, token, proxy, connection_factory=None):
        if not isinstance(token, str) or not token or '\n' in token or '\r' in token:
            raise Stop('github_credentials_required')
        self.token, self.proxy = token, proxy
        self.connection_factory = connection_factory or denied

    def get(self, path):
        root = r'/repos/leoronaldo10/AIFinance/'
        allowed = (root + r'actions/workflows/deploy-rebuilt\.yml',
                   root + r'actions/(runs|artifacts)/[1-9][0-9]{0,19}',
                   root + r'contents/\.github/workflows/deploy-rebuilt\.yml\?ref=' + client.SHA)
        if not isinstance(path, str) or not any(re.fullmatch(p, path) for p in allowed):
            raise Stop('github_path_denied')
        conn = self.connection_factory(self.proxy)
        try:
            conn.request('GET', path, headers={'Authorization':'Bearer '+self.token,
                'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',
                'User-Agent':'aifinance-fixed-release-review'})
            response = conn.getresponse()
            raw = response.read(1024*1024+1)
            if response.status != 200 or len(raw) > 1024*1024:
                raise Stop('github_evidence_unavailable')
            value = json.loads(raw)
            if not isinstance(value, dict): raise Stop('github_evidence_invalid')
            return value
        except Exception:
            raise Stop('github_evidence_unavailable') from None
        finally:
            close_bounded(conn.close)


def github_connection(proxy):
    conn = http.client.HTTPSConnection(proxy.host, proxy.port, timeout=12,
                                       context=client.reviewed.tls_context())
    headers = {'Proxy-Authorization':proxy.authorization} if proxy.authorization else {}
    conn.set_tunnel('api.github.com',443,headers=headers)
    return conn


class Transport:
    def __init__(self, api_factory=None, ws_factory=None):
        self.api_factory = api_factory or denied
        self.ws_factory = ws_factory or denied

    def start(self, proxy, path, headers):
        conn = self.api_factory(proxy,12)
        # A lost response after request starts may mean the command already ran.
        try:
            conn.request('POST',path,body=b'',headers=headers)
            response = conn.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise Stop('api_rejected_or_unknown_query_status')
            body = json.loads(raw)
            if not isinstance(body,dict) or body.get('Code'):
                raise Stop('api_rejected_or_unknown_query_status')
            return client.reviewed.validate_session(body)
        except Exception:
            raise Stop('api_unknown_no_replay_query_status') from None
        finally:
            close_bounded(conn.close)

    def websocket(self, url, proxy, token):
        return self.ws_factory(url,proxy,token)


class Journal:
    """Durable local no-replay ledger, held exclusively across one operation.

    Same-UID tampering is outside this boundary. No credentials or URLs are stored.
    The trusted application composition chooses this local directory, not the action.
    """
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700,parents=False,exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise Stop('journal_directory_untrusted')

    @contextlib.contextmanager
    def locked(self):
        # Exclusive nofollow lock also prevents concurrent duplicate API starts.
        fd = os.open(self.directory/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Stop('journal_lock_untrusted')
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Stop('operation_in_progress') from None
            path=self.directory/'operations.sqlite'
            if path.is_symlink():raise Stop('journal_untrusted')
            create=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            info=os.fstat(create);os.close(create)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Stop('journal_untrusted')
            with contextlib.closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE IF NOT EXISTS attempts (key TEXT PRIMARY KEY, command TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, receipt TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS uploads (sha TEXT PRIMARY KEY, digest TEXT NOT NULL, present INTEGER NOT NULL)')
                yield db
        finally:
            os.close(fd)


def admit_upload(size, seconds):
    # Explicit small-artifact MVP admission. This is a budget, not measured WAN performance.
    blocks=(size+767)//768
    if size > MAX_WIRE_BYTES or size <= 0 or 15 + (blocks+2)*0.25 > seconds:
        raise Stop('upload_size_or_budget_not_admitted')
    return blocks


def reserve(db, action, args):
    if action == 'artifact-status':
        db.execute('DELETE FROM uploads')
        db.commit()
        return
    if action == 'status':
        # A failed new status must not leave a stale resume authorization cached.
        db.execute('DELETE FROM observations')
        db.commit()
        return
    if action not in ('upload','deploy','rollback','resume'):return
    if action == 'resume':
        row=db.execute('SELECT receipt FROM observations WHERE id=?',(args[0],)).fetchone()
        if not row:raise Stop('explicit_status_required_before_resume')
        record=json.loads(row[0])
        if record['phase'] in ('succeeded','rolled_back','recovery_required'):
            raise Stop('terminal_operation_do_not_resume')
        db.execute('DELETE FROM observations WHERE id=?',(args[0],))
    else:
        key='upload:'+args[0] if action=='upload' else 'operation:'+args[-1]
        prior=db.execute('SELECT command FROM attempts WHERE key=?',(key,)).fetchone()
        if prior:
            observed=db.execute('SELECT digest,present FROM uploads WHERE sha=?',(args[0],)).fetchone() if action=='upload' else None
            if (not observed or observed != (args[1],0) or prior[0] != client.command(action,*args)):
                raise Stop('attempt_already_recorded_query_status')
        else:
            db.execute('INSERT INTO attempts VALUES (?,?)',(key,client.command(action,*args)))
    db.execute('DELETE FROM observations')
    db.execute('DELETE FROM uploads')
    db.commit()  # Before request(), including uncertain API errors; no automatic rollback.


@client.bounded
def operate(action, args, *, seconds, credentials, expiration, journal, transport,
            approval_reader=read_approval, github=None, checkout_reader=checkout_revision, bundle=None):
    """One explicit operation, full API/WS orchestration with dependency injection.

    apply is a local alias for the gateway's existing deploy verb. It does not upload
    implicitly. Status and resume are separate caller decisions, never automatic.
    """
    action = 'deploy' if action == 'apply' else action
    client.command(action,*args)
    proxy,_,path,headers=client.connection_plan(action,args,credentials,expiration,seconds)
    data=source=None
    with journal.locked() as db:
        if action in ('upload','deploy'):
            if github is None:raise Stop('independent_evidence_required')
            try: data,source=evidence.verify(args[0],args[1],bundle,approval_reader,github,checkout_reader)
            except Exception: raise Stop('independent_evidence_rejected') from None
            if action=='upload':admit_upload(len(data),seconds)
        elif bundle is not None and action != 'resume':
            raise Stop('unexpected_artifact')
        if action in ('rollback','resume'):
            approval=approval_reader()
            if approval.get('accepted') is not True or approval.get('version') != 1 or approval.get('repository') != evidence.REPO:
                raise Stop('approval_required')
            if action=='rollback' and args[0] not in approval.get('rollback_targets',[]):
                raise Stop('rollback_not_approved')
            if action=='resume':
                row=db.execute('SELECT receipt FROM observations WHERE id=?',(args[0],)).fetchone()
                if not row:raise Stop('explicit_status_required_before_resume')
                record=json.loads(row[0])
                if record['action']=='deploy':
                    # Re-check independent evidence and current checkout before resuming mutation.
                    try: evidence.verify(record['revision'],record['digest'],bundle,approval_reader,github,checkout_reader)
                    except Exception:raise Stop('independent_evidence_rejected') from None
                elif record['revision'] not in approval.get('rollback_targets',[]):
                    raise Stop('rollback_not_approved')
        reserve(db,action,args)
        url,sid,token=transport.start(proxy,path,headers)
        try:
            with websocket_scope(transport.websocket(url,proxy,token)) as ws:
                # Outer alarm covers evidence/API/WS I/O; cleanup has an additional <=2s bound.
                result=client.exchange.__wrapped__(ws,action,args,seconds=seconds,
                        **({'data':data,'source':source} if action=='upload' else {}))
        except Exception:
            raise Stop('session_unknown_no_replay_query_status') from None
        if action=='artifact-status':
            db.execute('INSERT OR REPLACE INTO uploads VALUES (?,?,?)',(args[0],args[1],int(result['present'])))
            db.commit()
        if action=='status' and result['operation'] is not None:
            record=result['operation']
            known=db.execute('SELECT command FROM attempts WHERE key=?',('operation:'+record['id'],)).fetchone()
            expected_args=[record['revision']] + ([record['digest']] if record['action']=='deploy' else []) + [record['id']]
            if known and known[0] != client.command(record['action'],*expected_args):
                raise Stop('observed_operation_conflicts_with_journal')
            db.execute('INSERT OR REPLACE INTO observations VALUES (?,?)',(record['id'],json.dumps(record)))
            db.commit()
        return result


def live_components(github_token):
    # Deliberate composition gate, not an OS security boundary. No env/CLI override.
    if not LIVE_EXECUTION_ENABLED:
        raise Stop('live_not_authorized')
    proxy=client.reviewed.require_proxy()
    return (Transport(client.reviewed.api_connection,client.reviewed.websocket_connect),
            GitHubEvidence(github_token,proxy,github_connection) if github_token else None)


def run_live(action, args, *, seconds, credentials, expiration, journal_directory,
             bundle=None, github_token=None):
    # Gate runs before credential processing, filesystem writes or connection creation.
    transport,github=live_components(github_token)
    return operate(action,args,seconds=seconds,credentials=credentials,expiration=expiration,
                   journal=Journal(journal_directory),transport=transport,github=github,bundle=bundle)


if __name__=='__main__':
    raise SystemExit('live_not_authorized')

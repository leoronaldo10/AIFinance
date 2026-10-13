#!/usr/bin/env python3
"""Full fake HTTPS API + fake WS + actual PTY + actual gateway/state/extractor."""
import base64
import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.parse
import zipfile

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module
s=load('session_adapter',ROOT/'deploy/native/rebuilt-proxy-session.py')
f=load('session_fixtures',ROOT/'scripts/tests/rebuilt-deploy-check.py')
REV=f.NEW;OP=f.ID
WORKFLOW=(ROOT/'.github/workflows/deploy-rebuilt.yml').read_bytes()


def frame(payload,seq=1,kind=1):
    return struct.pack('<I',kind)+b'1.02'+b'\x07fixture\0'+struct.pack('<QIIHBB',0,0,seq,len(payload),0,0)+payload

class Response:
    status=200
    def __init__(self,value):self.raw=json.dumps(value).encode()
    def read(self,limit):return self.raw[:limit]

class FakeGitHub:
    def __init__(self,values):self.values=values;self.calls=[]
    def connection(self,proxy):
        owner=self
        class Connection:
            def request(self,method,path,headers):
                assert method=='GET'
                owner.calls.append(path);self.path=path
            def getresponse(self):return Response(owner.values[self.path])
            def close(self):pass
        return Connection()

class PtySocket:
    def __init__(self,process,master):self.process=process;self.master=master;self.seq=0;self.sent=[];self.bad=None
    def __enter__(self):return self
    def __exit__(self,*args):
        os.close(self.master)
        if self.process.poll() is None:
            try:self.process.wait(timeout=.3)
            except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=2)
    def recv(self,timeout):
        if self.bad: return self.bad
        if not select.select([self.master],[],[],timeout)[0]:raise TimeoutError()
        try:raw=os.read(self.master,8192)
        except OSError:raw=b''
        if not raw:return frame(b'\x06',kind=5)
        self.seq+=1
        return frame(raw,self.seq)
    def send(self,raw):
        decoded=s.client.reviewed.decode_frame(raw)
        self.sent.append(decoded)
        os.write(self.master,decoded.payload)

class Cloud:
    def __init__(self,root):
        self.root=root;self.requests=[];self.sockets=[];self.mode='normal';self.lost=False;self.api_delay=0;self.bad_url=False;self.bad_frame=None;self.ws_lost=False
    def connection(self,proxy,timeout):
        owner=self
        class Connection:
            def request(self,method,path,body,headers):
                assert method=='POST' and body==b''
                params=urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                assert params['InstanceId.1']==[s.client.reviewed.INSTANCE]
                assert params['Username']==[s.client.reviewed.USERNAME]
                assert headers['authorization'].startswith('ACS3-HMAC-SHA256')
                argv=params['CommandLine'][0].split(' ')
                assert argv[0]==s.client.GATEWAY
                owner.requests.append(params)
                if owner.api_delay:time.sleep(owner.api_delay)
                master,slave=pty.openpty()
                process=subprocess.Popen([sys.executable,'-B',str(ROOT/'scripts/tests/fixtures/rebuilt-proxy-receiver.py'),str(owner.root),owner.mode,*argv[1:]],
                    stdin=slave,stdout=slave,stderr=slave,close_fds=True)
                os.close(slave)
                owner.sockets.append(PtySocket(process,master))
            def getresponse(self):
                if owner.lost:raise ConnectionError('fake secret must not appear')
                host='evil.invalid' if owner.bad_url else s.client.reviewed.WSS_HOST
                return Response({'SessionId':'fixture','SecurityToken':'fake-token',
                    'WebSocketUrl':'wss://'+host+'/session?sessionId=fixture&token=fake-token'})
            def close(self):pass
        return Connection()
    def websocket(self,url,proxy,token):
        assert token=='fake-token'
        if self.ws_lost:raise ConnectionError('fake ws lost')
        self.sockets[-1].bad=self.bad_frame
        return self.sockets[-1]
    def cleanup(self):
        for ws in self.sockets:
            if ws.process.poll() is None:ws.process.terminate();ws.process.wait(timeout=2)
            with contextlib.suppress(OSError):os.close(ws.master)

class Session(f.Fixture):
    def setUp(self):
        super().setUp()
        target=self.make(REV)
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w:gz') as tar:tar.add(target,arcname='.')
        self.data=raw.getvalue();self.digest=hashlib.sha256(self.data).hexdigest()
        shutil.rmtree(target)
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as archive:
            archive.writestr(REV+'.tar.gz',self.data)
            archive.writestr(REV+'.tar.gz.sha256',self.digest+'  '+REV+'.tar.gz\n')
        self.bundle=raw.getvalue()
        self.p['approved_artifacts'][REV]=self.digest
        (self.root/'fixture-policy.json').write_text(json.dumps(self.p))
        entry=dict(sha256=self.digest,run_id=123,artifact_id=456,workflow_id=789,run_attempt=1,
                   workflow_sha256=hashlib.sha256(WORKFLOW).hexdigest())
        self.approval=dict(version=1,accepted=True,repository=s.evidence.REPO,artifacts={REV:entry},rollback_targets=[f.OLD])
        prefix='/repos/'+s.evidence.REPO
        self.values={prefix+'/actions/workflows/deploy-rebuilt.yml':{'id':789,'path':s.evidence.WORKFLOW},
          prefix+'/actions/runs/123':dict(id=123,workflow_id=789,path=s.evidence.WORKFLOW,head_sha=REV,run_attempt=1,
            event='workflow_dispatch',status='completed',conclusion='success',repository={'full_name':s.evidence.REPO},head_repository={'full_name':s.evidence.REPO}),
          prefix+'/actions/artifacts/456':dict(id=456,name='aifinance-'+REV,expired=False,workflow_run={'id':123,'head_sha':REV},digest='sha256:'+hashlib.sha256(self.bundle).hexdigest()),
          prefix+'/contents/'+s.evidence.WORKFLOW+'?ref='+REV:dict(path=s.evidence.WORKFLOW,encoding='base64',content=base64.b64encode(WORKFLOW).decode())}
        self.gh=FakeGitHub(self.values)
        self.github=s.GitHubEvidence('fake-github-token',s.client.reviewed.Proxy('http://127.0.0.1:9','127.0.0.1',9,None),self.gh.connection)
        self.cloud=Cloud(self.root)
        self.transport=s.Transport(self.cloud.connection,self.cloud.websocket)
        self.journal=s.Journal(self.root/'journal')
        self.proxy=patch.object(s.client.reviewed.urllib.request,'getproxies',return_value={'https':'http://127.0.0.1:9','no':'*'})
        self.proxy.start()
    def tearDown(self):
        self.cloud.cleanup();self.proxy.stop();super().tearDown()
    def call(self,action,args,**kwargs):
        options=dict(seconds=30,credentials=('fake-id','fake-secret','fake-sts'),
          expiration=dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),journal=self.journal,transport=self.transport,
          approval_reader=lambda:copy.deepcopy(self.approval),github=self.github,checkout_reader=lambda:REV)
        if action in ('upload','deploy','apply','resume'):options['bundle']=self.bundle
        options.update(kwargs)
        return s.operate(action,args,**options)
    def upload(self):return self.call('upload',[REV,self.digest])

    def test_full_api_ws_pty_upload_apply_status_rollback(self):
        self.assertEqual(self.upload()['sha256'],self.digest)
        self.assertEqual((self.root/'incoming'/(REV+'.tar.gz')).read_bytes(),self.data)
        self.assertTrue(self.call('artifact-status',[REV,self.digest])['present'])
        self.assertEqual(self.call('apply',[REV,self.digest,OP])['phase'],'succeeded')
        self.assertEqual(self.call('status',[OP])['operation']['revision'],REV)
        self.assertEqual(self.call('rollback',[f.OLD,'2'*32])['phase'],'succeeded')
        self.assertEqual((self.root/'restarts').read_text(),'2')
        self.assertEqual(len(self.cloud.requests),5)
        self.assertEqual(len(self.gh.calls),8)

    def test_interruption_explicit_status_resume_and_no_repeat(self):
        self.upload();self.cloud.mode='interrupt-checking'
        with self.assertRaises(s.Stop):self.call('apply',[REV,self.digest,OP])
        count=len(self.cloud.requests)
        # Persistent ledger works after a fresh Journal object (process rebuild).
        self.journal=s.Journal(self.root/'journal')
        with self.assertRaises(s.Stop):self.call('apply',[REV,self.digest,OP])
        with self.assertRaises(s.Stop):self.call('resume',[OP])
        self.assertEqual(len(self.cloud.requests),count)
        self.cloud.mode='normal'
        self.assertEqual(self.call('status',[OP])['operation']['phase'],'checking')
        self.assertEqual(self.call('resume',[OP])['phase'],'succeeded')
        self.assertEqual((self.root/'restarts').read_text(),'1')
        with self.assertRaises(s.Stop):self.call('resume',[OP])

    def test_lost_api_reply_after_side_effect_does_not_replay(self):
        self.upload();self.cloud.lost=True
        with self.assertRaises(s.Stop) as caught:self.call('apply',[REV,self.digest,OP])
        self.assertNotIn('fake secret',str(caught.exception))
        self.cloud.sockets[-1].process.wait(timeout=3)
        count=len(self.cloud.requests)
        with self.assertRaises(s.Stop):self.call('apply',[REV,self.digest,OP])
        self.assertEqual(len(self.cloud.requests),count)
        self.cloud.lost=False
        self.assertEqual(self.call('status',[OP])['operation']['phase'],'succeeded')
        with self.assertRaises(s.Stop):self.call('resume',[OP])
        self.assertEqual((self.root/'restarts').read_text(),'1')

    def test_no_api_for_expired_fake_credentials_or_wrong_source(self):
        with self.assertRaises(s.Stop):self.call('status',[],expiration=dt.datetime(2000,1,1,tzinfo=dt.timezone.utc))
        base=copy.deepcopy(self.values)
        cases=[('/actions/runs/123','head_sha','a'*40),('/actions/runs/123','workflow_id',1),
          ('/actions/runs/123','conclusion','failure'),('/actions/runs/123','run_attempt',2),
          ('/actions/runs/123','event','pull_request'),('/actions/runs/123','head_repository',{'full_name':'attacker/fork'}),
          ('/actions/artifacts/456','digest','sha256:'+'0'*64),('/actions/artifacts/456','expired',True),
          ('/actions/artifacts/456','workflow_run',{'id':999,'head_sha':REV})]
        for suffix,key,value in cases:
            self.values.clear();self.values.update(copy.deepcopy(base))
            self.values['/repos/'+s.evidence.REPO+suffix][key]=value
            with self.subTest(key=key),self.assertRaises(s.Stop):self.upload()
        self.values.clear();self.values.update(base)
        with self.assertRaises(s.Stop):self.call('upload',[REV,self.digest],checkout_reader=lambda:'c'*40)
        with self.assertRaises(s.Stop):self.call('upload',[REV,self.digest],approval_reader=lambda:{})
        with self.assertRaises(s.Stop):self.call('upload',[REV,self.digest],bundle=self.bundle+b'corrupt')
        self.assertFalse(self.cloud.requests)

    def test_outer_digest_cannot_substitute_for_approved_inner_bytes(self):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as archive:
            archive.writestr(REV+'.tar.gz',b'different')
            archive.writestr(REV+'.tar.gz.sha256',self.digest+'  '+REV+'.tar.gz\n')
        bad=raw.getvalue()
        self.values['/repos/'+s.evidence.REPO+'/actions/artifacts/456']['digest']='sha256:'+hashlib.sha256(bad).hexdigest()
        with self.assertRaises(s.Stop):self.call('upload',[REV,self.digest],bundle=bad)
        self.assertFalse(self.cloud.requests)

    def test_max_admitted_size_real_pty(self):
        self.data=bytes(range(256))*4096
        self.digest=hashlib.sha256(self.data).hexdigest()
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w') as archive:
            archive.writestr(REV+'.tar.gz',self.data)
            archive.writestr(REV+'.tar.gz.sha256',self.digest+'  '+REV+'.tar.gz\n')
        self.bundle=raw.getvalue()
        self.approval['artifacts'][REV]['sha256']=self.digest
        self.p['approved_artifacts'][REV]=self.digest
        (self.root/'fixture-policy.json').write_text(json.dumps(self.p))
        self.values['/repos/'+s.evidence.REPO+'/actions/artifacts/456']['digest']='sha256:'+hashlib.sha256(self.bundle).hexdigest()
        started=time.monotonic()
        self.call('upload',[REV,self.digest],seconds=480)
        elapsed=time.monotonic()-started
        self.assertEqual((self.root/'incoming'/(REV+'.tar.gz')).read_bytes(),self.data)
        self.assertEqual(len(self.cloud.sockets[-1].sent),1367)
        print(json.dumps({'local_pty_1mib_seconds':round(elapsed,3),'input_frames':1367}))

    def test_api_timeout_and_endpoint_fail_closed(self):
        self.cloud.api_delay=2
        started=time.monotonic()
        with self.assertRaises(s.Stop):self.call('status',[],seconds=1)
        self.assertLess(time.monotonic()-started,1.8)
        self.cloud.api_delay=0;self.cloud.bad_url=True
        with self.assertRaises(s.Stop):self.call('status',[])
        self.assertFalse(self.cloud.sockets[-1].sent)

    def test_ws_disconnect_wrong_version_and_sequence_no_replay(self):
        self.cloud.ws_lost=True
        with self.assertRaises(s.Stop):self.upload()
        self.assertEqual(len(self.cloud.requests),1)
        with self.assertRaises(s.Stop):self.upload()
        self.assertEqual(len(self.cloud.requests),1)
        self.cloud.ws_lost=False
        for bad in [frame(b'x')[:4]+b'9.99'+frame(b'x')[8:],frame(b'x',seq=2),frame(b'',kind=6)]:
            self.cloud.bad_frame=bad
            with self.assertRaises(s.Stop):self.call('status',[])
            self.assertFalse(self.cloud.sockets[-1].sent)

    def test_upload_explicit_missing_status_permits_one_manual_retry(self):
        self.cloud.ws_lost=True
        with self.assertRaises(s.Stop):self.upload()
        # Fake remote process ends; in real use the gateway lock/time limit must settle first.
        self.cloud.sockets[-1].__exit__()
        self.cloud.ws_lost=False
        with self.assertRaises(s.Stop):self.upload()
        self.assertFalse(self.call('artifact-status',[REV,self.digest])['present'])
        self.assertEqual(self.upload()['sha256'],self.digest)
        self.assertTrue(self.call('artifact-status',[REV,self.digest])['present'])
        with self.assertRaises(s.Stop):self.upload()

    def test_status_failure_revokes_cached_resume(self):
        self.upload();self.cloud.mode='interrupt-checking'
        with self.assertRaises(s.Stop):self.call('apply',[REV,self.digest,OP])
        self.cloud.mode='normal'
        self.call('status',[OP])
        self.cloud.bad_url=True
        with self.assertRaises(s.Stop):self.call('status',[OP])
        self.cloud.bad_url=False
        count=len(self.cloud.requests)
        with self.assertRaises(s.Stop):self.call('resume',[OP])
        self.assertEqual(len(self.cloud.requests),count)

    def test_github_transport_refuses_redirect_and_arbitrary_paths(self):
        with self.assertRaises(s.Stop):self.github.get('https://evil.invalid/data')
        self.assertFalse(self.gh.calls)
        class Redirect:
            status=302
            def read(self,n):return b'{}'
        conn=self.gh.connection(None)
        conn.getresponse=lambda:Redirect()
        with patch.object(self.github,'connection_factory',return_value=conn):
            with self.assertRaises(s.Stop):self.github.get('/repos/'+s.evidence.REPO+'/actions/runs/123')
        with self.assertRaises(s.Stop):s.Transport().start(None,'/',{})

    def test_timeout_cleanup_has_independent_bound(self):
        class Blocked:
            def __enter__(self):return self
            def __exit__(self,*args):time.sleep(10)
            def recv(self,timeout):time.sleep(10)
        with patch.object(self.transport,'websocket',return_value=Blocked()):
            started=time.monotonic()
            with self.assertRaises(s.Stop):self.call('status',[],seconds=1)
            self.assertLess(time.monotonic()-started,3.7)
            self.assertEqual(len(self.cloud.requests),1)

    def test_upload_admission_and_deadline_budget(self):
        self.assertEqual(s.admit_upload(1024*1024,480),1366)
        for size,seconds in [(128*1024*1024,480),(1024*1024+1,480),(1024*1024,30),(1,1)]:
            with self.assertRaises(s.Stop):s.admit_upload(size,seconds)
        # Deterministic pessimistic modeled RTT, no performance promise or real sleep.
        self.assertLess(15+(1366+2)*.25,480)
        with self.assertRaises(s.Stop):s.live_components('fake')
        with self.assertRaises(s.Stop):
            s.run_live('status',[],seconds=30,credentials=None,expiration=None,journal_directory=self.root/'must-not-create')
        self.assertFalse((self.root/'must-not-create').exists())

if __name__=='__main__':
    names=[name for name in Session.__dict__ if name.startswith('test_')]
    with patch.object(socket,'create_connection',side_effect=AssertionError('network forbidden')),\
         patch.object(socket.socket,'connect',side_effect=AssertionError('network forbidden')),\
         patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS forbidden')):
        result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Session(name) for name in names))
        sys.exit(not result.wasSuccessful())

#!/usr/bin/env python3
"""No cloud I/O: real local PTY + upload, real gateway state machine fixtures."""
import base64
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

c = load('adapter', ROOT/'deploy/native/rebuilt-proxy.py')
f = load('gateway_fixtures', ROOT/'scripts/tests/rebuilt-deploy-check.py')
g = f.m
REV = 'b'*40
OP = '1'*32
DATA = bytes(range(256))*20
DIG = hashlib.sha256(DATA).hexdigest()
SOURCE = dict(repository='leoronaldo10/AIFinance', revision=REV, sha256=DIG,
              checks_passed=True, build_run='123')

def output(data, sequence=1, kind=1, version=b'1.02', channel=b'fixture'):
    return (struct.pack('<I', kind)+version+bytes([len(channel)])+channel+b'\0'+
            struct.pack('<QIIHBB', 0, 0, sequence, len(data), 0, 0)+data)

def response(value):
    return json.dumps(value).encode()+b'\r\n'

class WS:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.sent = []
    def recv(self, **kwargs):
        return next(self.frames)
    def send(self, raw):
        self.sent.append(c.reviewed.decode_frame(raw))

class Adapter(unittest.TestCase):
    def test_commands_direct_short_no_shell(self):
        for action, args in [('verify', []), ('status', []), ('status', [OP]),
                ('resume', [OP]), ('upload', [REV,DIG]), ('deploy',[REV,DIG,OP]),
                ('rollback',[REV,OP])]:
            line = c.command(action,*args)
            self.assertLessEqual(len(line),512)
            self.assertEqual(g.terminal_command(line.split()[1:]),' '.join(line.split()[2:]))
        for bad in ['../a','main','b'*39,'B'*40,REV+'\n',REV+';id',REV+' x']:
            with self.subTest(bad=bad), self.assertRaises(c.Stop): c.command('upload',bad,DIG)
        for action,args in [('upload',[REV+' '+DIG]),('deploy',[REV+' '+DIG+' '+OP]),('status',[''])]:
            with self.assertRaises(c.Stop):c.command(action,*args)
        for action in ['shell','logs','inspect','upload;id']:
            with self.assertRaises(c.Stop): c.command(action)

    def test_signed_request_and_expiration(self):
        future = dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)
        path, headers = c.signed_request('status',[],('fake-id','fake-secret','fake-token'),future,480)
        self.assertIn('CommandLine=',path)
        self.assertIn('ACS3-HMAC-SHA256',headers['authorization'])
        self.assertEqual(headers['host'],c.reviewed.API_HOST)
        for expiration in [dt.datetime(2000,1,1,tzinfo=dt.timezone.utc),dt.datetime.now(),None]:
            with self.assertRaises(c.Stop): c.signed_request('status',[],('a','b','c'),expiration,480)
        with self.assertRaises(c.Stop): c.connect_live()

    def test_connection_plan_requires_proxy_and_verified_tls(self):
        future=dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)
        with patch.object(c.reviewed.urllib.request,'getproxies',return_value={}):
            with self.assertRaises(c.Stop):c.connection_plan('status',[],('a','b','c'),future,60)
        with patch.object(c.reviewed.urllib.request,'getproxies',return_value={'https':'http://127.0.0.1:9','no':'*'}):
            proxy,tls,path,headers=c.connection_plan('status',[],('a','b','c'),future,60)
        import ssl
        self.assertEqual(proxy.url,'http://127.0.0.1:9')
        self.assertTrue(tls.check_hostname)
        self.assertEqual(tls.verify_mode,ssl.CERT_REQUIRED)
        with self.assertRaises(c.Stop):c.reviewed.validate_session({'SessionId':'fake','SecurityToken':'fake',
            'WebSocketUrl':'wss://evil.example/session?sessionId=fake&token=fake'})

    def test_artifact_provenance_digest_size(self):
        self.assertEqual(c.artifact(DATA,REV,DIG,SOURCE),DATA)
        for data, source in [(b'',SOURCE),(b'bad',SOURCE),(DATA,{}),(DATA,dict(SOURCE,revision='a'*40)),
                (DATA,dict(SOURCE,checks_passed=False)),(DATA,dict(SOURCE,build_run='https://evil'))]:
            with self.assertRaises(c.Stop): c.artifact(data,REV,DIG,source)
        with patch.object(c,'LIMIT',len(DATA)-1), self.assertRaises(c.Stop): c.artifact(DATA,REV,DIG,SOURCE)

    def test_status_duplicate_output(self):
        frame=output(response({'protocol':'rebuilt-v1','operation':None,'current':REV}))
        ws=WS([frame,frame,output(b'\x06',kind=5)])
        self.assertEqual(c.exchange(ws,'status',[],seconds=1)['operation'],None)
        self.assertFalse(ws.sent)
        for record in [[], {'id':'bad'}]:
            bad=WS([output(response({'protocol':'rebuilt-v1','current':REV,'operation':record})),output(b'\x06',kind=5)])
            with self.assertRaises(c.Stop):c.exchange(bad,'status',[],seconds=1)

    def test_bad_protocol_disconnect_and_versions(self):
        for frames in [[],[b'bad'],[output(b'x',version=b'1.01')],
                [output(b'x',sequence=2)], [output(b'\x02',kind=5)],
                [output(b'\x06',kind=5)], [output(response({'protocol':'wrong'})),output(b'\x06',kind=5)],
                [output(b'{}\n'),output(b'\x06',kind=5,channel=b'other')]]:
            ws=WS(frames)
            with self.subTest(frames=frames), self.assertRaises(c.Stop): c.exchange(ws,'status',[],seconds=1)
            self.assertFalse(ws.sent)

    def test_upload_disconnect_never_replays(self):
        ws=WS([output(response({'terminal':'rebuilt-pty-v1','ack':0}))])
        with self.assertRaises(c.Stop): c.exchange(ws,'upload',[REV,DIG],seconds=1,data=DATA,source=SOURCE)
        self.assertEqual(len(ws.sent),1)
        self.assertEqual(ws.sent[0].input_seq,1)

    def test_wrong_duplicate_ack_and_no_input_for_status(self):
        for action,args in [('upload',[REV,DIG]),('status',[])]:
            ws=WS([output(response({'terminal':'rebuilt-pty-v1','ack':0})),
                   output(response({'terminal':'rebuilt-pty-v1','ack':0}),sequence=2)])
            with self.assertRaises(c.Stop): c.exchange(ws,action,args,seconds=1,
                    **({'data':DATA,'source':SOURCE} if action=='upload' else {}))
            self.assertEqual(len(ws.sent),1 if action=='upload' else 0)

    def test_decoder_rejects_truncation_duplicate_noncanonical_and_limit(self):
        good=b'00000001:'+base64.b64encode(b'abc')+b'\n'
        for body in [b'',b'a'*1040, b'00000002:YWJj\n',b'00000001:!!!!\n', b'00000001:Zh==\n']:
            with self.subTest(body=body), self.assertRaises(g.Refused):
                g.TerminalUpload(io.BytesIO(body),lambda _:None).read(65536)
        reader=g.TerminalUpload(io.BytesIO(good+good),lambda _:None)
        self.assertEqual(reader.read(65536),b'abc')
        with self.assertRaises(g.Refused):reader.read(65536)
        with patch.object(g,'LIMIT',2),self.assertRaises(g.Refused):
            g.TerminalUpload(io.BytesIO(good),lambda _:None).read(65536)

    def test_empty_channel_and_blocked_send(self):
        ws=WS([output(response({'terminal':'rebuilt-pty-v1','ack':0})),
               output(response({'terminal':'rebuilt-pty-v1','ack':1}),sequence=2,channel=b'')])
        with self.assertRaises(c.Stop): c.exchange(ws,'upload',[REV,DIG],seconds=1,data=DATA,source=SOURCE)
        self.assertEqual(len(ws.sent),1)
        ws=WS([output(response({'terminal':'rebuilt-pty-v1','ack':0}))])
        import time
        with patch.object(ws,'send',side_effect=lambda _:time.sleep(5)) as send:
            started=time.monotonic()
            with self.assertRaises(c.Stop): c.exchange(ws,'upload',[REV,DIG],seconds=1,data=DATA,source=SOURCE)
            self.assertLess(time.monotonic()-started,2)
            self.assertEqual(send.call_count,1)

    def test_real_pty_binary_upload(self):
        # Agent creates a default canonical PTY too. No raw-mode assumption.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp)/'incoming').mkdir()
            script = '''import importlib.util,sys,json
from pathlib import Path
spec=importlib.util.spec_from_file_location('g',sys.argv[1]);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
g.ROOT=Path(sys.argv[2])
print(json.dumps(g.upload(sys.argv[3],sys.argv[4],g.terminal_input())),flush=True)
'''
            master,slave=pty.openpty()
            process=subprocess.Popen([sys.executable,'-B','-c',script,str(ROOT/'deploy/native/rebuilt-gateway.py'),tmp,REV,DIG],
                                     stdin=slave,stdout=slave,stderr=slave,close_fds=True)
            os.close(slave)
            class PtyWS:
                seq=0
                def recv(self,timeout):
                    if not select.select([master],[],[],timeout)[0]: raise TimeoutError()
                    try: raw=os.read(master,8192)
                    except OSError: raw=b''
                    if not raw:return output(b'\x06',kind=5)
                    self.seq+=1
                    return output(raw,self.seq)
                def send(self,raw):
                    frame=c.reviewed.decode_frame(raw)
                    os.write(master,frame.payload)
            try:
                result=c.exchange(PtyWS(),'upload',[REV,DIG],seconds=10,data=DATA,source=SOURCE)
                self.assertEqual(result,{'uploaded':REV,'sha256':DIG})
                self.assertEqual((Path(tmp)/'incoming'/(REV+'.tar.gz')).read_bytes(),DATA)
                self.assertEqual(process.wait(timeout=2),0)
            finally:
                if process.poll() is None: process.kill();process.wait()
                os.close(master)

class Integration(f.Fixture):
    # The existing fixture uses real receipts/symlinks/publish, only host services mocked.
    def test_adapter_rollback_status_duplicate_resume(self):
        self.make(f.NEW)
        result=self.publish()
        def check(action,args,result):
            return c.exchange(WS([output(response(result)),output(b'\x06',kind=5)]),action,args,seconds=1)
        self.assertEqual(check('rollback',[f.NEW,f.ID],result)['phase'],'succeeded')
        count=self.restart_count
        duplicate=self.publish()
        check('resume',[f.ID],duplicate)
        self.assertEqual(self.restart_count,count)
        record=g.receipt(self.state,f.ID)
        check('status',[f.ID],{'protocol':'rebuilt-v1','operation':record,'current':g.current_sha(self.p)})
        with self.assertRaises(c.Stop):check('rollback',['c'*40,f.ID],result)
        with self.assertRaises(g.Refused):self.publish(sha=f.OLD)
        for change in [{'action':'deploy','digest':'f'*64},{'updated':True},{'fallback_allowed':1}]:
            with self.assertRaises(c.Stop):check('rollback',[f.NEW,f.ID],dict(result,**change))

    def test_deploy_extraction_receipt_digest_and_interrupted_resume(self):
        # Reuse the actual extraction integration, then bind its persisted receipt to transport.
        self.test_deploy_uses_existing_reviewed_extractor_and_then_can_retry()
        record=g.receipt(self.state,f.ID)
        frames=lambda value:[output(response(value)),output(b'\x06',kind=5)]
        args=[f.NEW,record['digest'],f.ID]
        self.assertEqual(c.exchange(WS(frames(record)),'deploy',args,seconds=1),record)
        with self.assertRaises(c.Stop):
            c.exchange(WS(frames(dict(record,digest='f'*64))),'deploy',args,seconds=1)
        # Simulate response loss after gateway completed; only status then explicit resume.
        with self.assertRaises(c.Stop):c.exchange(WS([]),'deploy',args,seconds=1)
        count=self.restart_count
        status={'protocol':'rebuilt-v1','current':f.NEW,'operation':g.receipt(self.state,f.ID)}
        c.exchange(WS(frames(status)),'status',[f.ID],seconds=1)
        resumed=g.publish(self.p,self.state,'deploy',f.NEW,record['digest'],f.ID)
        c.exchange(WS(frames(resumed)),'resume',[f.ID],seconds=1)
        self.assertEqual(self.restart_count,count)

    def test_artifact_status_main(self):
        g.upload(REV,DIG,io.BytesIO(DATA))
        self.p['approved_artifacts'][REV]=DIG
        with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':'rebuilt-v1 artifact-status '+REV+' '+DIG}), \
             patch.object(g,'policy',return_value=self.p), \
             patch.object(g.os,'getuid',return_value=os.getuid()), patch.object(g.os,'geteuid',return_value=os.getuid()), \
             patch.object(g.pwd,'getpwuid') as user:
            user.return_value.pw_name='aifinance-deploy'
            old_umask=os.umask(0o077)
            try: result=g.main()
            finally: os.umask(old_umask)
        self.assertTrue(result['present'])
        self.assertTrue(c.exchange(WS([output(response(result)),output(b'\x06',kind=5)]),
                                  'artifact-status',[REV,DIG],seconds=1)['present'])

if __name__=='__main__':
    # Guard accidental cloud/socket use in all in-process tests.
    with patch.object(socket,'create_connection',side_effect=AssertionError('network forbidden')),\
         patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS forbidden')):
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Adapter),
                                 Integration('test_adapter_rollback_status_duplicate_resume'),
                                 Integration('test_artifact_status_main'),
                                 Integration('test_deploy_extraction_receipt_digest_and_interrupted_resume')])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        sys.exit(not result.wasSuccessful())

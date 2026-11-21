import importlib.util,json,os,pathlib,subprocess,tempfile,unittest,datetime
P=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('observer',P/'observe.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class PassiveObserver(unittest.TestCase):
    def test_fixed_command_and_clean_environment(self):
        calls=[]
        def run(args,**kw):
            calls.append((args,kw));return subprocess.CompletedProcess(args,0,'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n','SECRET')
        result=m.snapshot(run)
        self.assertEqual(result['activeState'],'active');self.assertNotIn('SECRET',json.dumps(result))
        args,kw=calls[0];self.assertEqual(args,m.COMMAND);self.assertEqual(args[2],'aifinance-native-resident.service');self.assertNotIn('shell',kw);self.assertEqual(kw['env'],{'PATH':'/usr/bin:/bin','LANG':'C'});self.assertEqual(kw['timeout'],5)
    def test_failure_missing_and_unknown_never_claim_running(self):
        for code,text in [(1,'ActiveState=active\n'),(0,'LoadState=not-found\nActiveState=inactive\nUnitFileState=SECRET\n'),(0,'ActiveState=SECRET\n'),(0,'x'*1025)]:
            result=m.snapshot(lambda *a,**kw:subprocess.CompletedProcess(a,code,text,'SECRET'))
            self.assertNotEqual(result['activeState'],'active');self.assertNotIn('SECRET',json.dumps(result))
        def timeout(*a,**kw):raise subprocess.TimeoutExpired('fixed',5,stderr='SECRET')
        self.assertEqual(m.snapshot(timeout)['activeState'],'unknown')
    def test_failed_service_is_explicit_and_time_is_not_inferred(self):
        now=datetime.datetime(2026,11,21,tzinfo=datetime.timezone.utc)
        result=m.snapshot(lambda *a,**kw:subprocess.CompletedProcess(a,0,'LoadState=loaded\nActiveState=failed\nUnitFileState=enabled\n',''),now)
        self.assertEqual(result['activeState'],'failed');self.assertEqual(result['observedAt'],now.isoformat());self.assertEqual(set(result),{'format','unit','observedAt','activeState','loadState','unitFileState'})
    def test_atomic_snapshot_permissions_and_no_other_files(self):
        with tempfile.TemporaryDirectory()as td:
            p=pathlib.Path(td);m.write_snapshot(m.snapshot(lambda *a,**kw:subprocess.CompletedProcess(a,1,'','')),p)
            out=p/'status.json';self.assertEqual(out.stat().st_mode&0o777,0o640);self.assertEqual(list(p.iterdir()),[out]);self.assertEqual(json.loads(out.read_text())['activeState'],'unknown')
            m.write_snapshot(m.snapshot(lambda *a,**kw:subprocess.CompletedProcess(a,0,'ActiveState=active\nLoadState=loaded\nUnitFileState=enabled\n','')),p)
            self.assertEqual(json.loads(out.read_text())['activeState'],'active')
    def test_unsafe_directory_rejected(self):
        with tempfile.TemporaryDirectory()as td:
            p=pathlib.Path(td);p.chmod(0o777)
            with self.assertRaises(ValueError):m.write_snapshot({},p)
            self.assertEqual(list(p.iterdir()),[])
            p.chmod(0o700)
    def test_unit_has_no_credentials_network_or_elevated_rights(self):
        text=(P/'aifinance-collection-observer.service').read_text()
        for token in ['NoNewPrivileges=true','CapabilityBoundingSet=','PrivateNetwork=true','RestrictAddressFamilies=AF_UNIX','ProtectSystem=strict','RuntimeDirectoryMode=0750']:self.assertIn(token,text)
        for token in ['LoadCredential','EnvironmentFile','sudo','ExecStartPre','aifinance-native-resident.service start']:self.assertNotIn(token,text)
if __name__=='__main__':unittest.main()

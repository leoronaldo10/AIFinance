import contextlib,io,pathlib,runpy,tempfile,unittest,json,hashlib,os,types,shutil
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
M=runpy.run_path(str(R/'configure.py'))
class ConfigureUX(unittest.TestCase):
 def test_visible_inputs_allow_hyphen(self):
  prompts=[];answers=iter(['fixture_db','65439','fixture_app','fixture-deploy'])
  def answer(prompt):prompts.append(prompt);return next(answers)
  with patch('builtins.input',side_effect=answer):result=M['read_bindings']()
  self.assertEqual(result,('fixture_db',65439,'fixture_app','fixture-deploy'))
  self.assertTrue(all('visible' in p for p in prompts))
 def test_invalid_field_is_named_without_echo(self):
  for values,reason in [(['bad secret URI'],'invalid_database_name'),(['fixture','SECRET'],'invalid_database_port'),(['fixture','0'],'invalid_database_port'),(['fixture','65439','bad secret'],'invalid_application_role'),(['fixture','65439','fixture','bad secret'],'invalid_deploy_account')]:
   with self.subTest(reason=reason),patch('builtins.input',side_effect=values):
    with self.assertRaisesRegex(M['Refused'],reason):M['read_bindings']()
 def test_preview_and_explicit_confirmation(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out),patch('builtins.input',return_value='CONFIRM'):M['confirm_bindings']('a'*64,'fixture',65439,'fixture_app','fixture-deploy')
  for field in ['artifact_sha256=','database=fixture','port=65439','application_role=fixture_app','deploy_account=fixture-deploy']:self.assertIn(field,out.getvalue())
 def test_cancel_refuses(self):
  with contextlib.redirect_stdout(io.StringIO()),patch('builtins.input',return_value='no'):
   with self.assertRaisesRegex(M['Refused'],'confirmation_cancelled'):M['confirm_bindings']('a'*64,'fixture',65439,'fixture_app','fixture-deploy')
 def test_exception_payload_never_printed(self):
  for e in [KeyError('SECRET'),ValueError('SECRET'),OSError('SECRET')]:self.assertNotIn('SECRET',M['failure_message'](e))
  self.assertIn('input_ended',M['failure_message'](EOFError()))
 def test_render_failure_precedes_directory_creation(self):
  with tempfile.TemporaryDirectory() as d:
   dest=pathlib.Path(d)/'review'
   with self.assertRaisesRegex(M['Refused'],'unresolved_template'):M['render'](dest,{})
   self.assertFalse(dest.exists())
 def test_compatible_builder_is_exact_and_components_unchanged(self):
  M['verify_build_helper'](M['COMPATIBLE_BUILD_HELPER'],'f'*40)
  M['verify_build_helper']('f'*40,'f'*40)
  for old in ['6e2021eb58cf4d4f73f8c0de07eda957510c44bf','a'*40]:
   with self.assertRaisesRegex(M['Refused'],'incompatible_build_helper'):M['verify_build_helper'](old,'f'*40)
 def test_compatible_builder_rejects_changed_component(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d)
   for name in M['BUILD_COMPONENT_HASHES']:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/name,p)
   (root/'runtime-probe.mjs').write_text('changed')
   with patch.dict(M['verify_build_helper'].__globals__,{'HERE':root}):
    with self.assertRaisesRegex(M['Refused'],'compatible_build_component_changed'):M['verify_build_helper'](M['COMPATIBLE_BUILD_HELPER'],'f'*40)
 def run_main_fixture(self,answer):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);build=root/'build';build.mkdir();target=root/'review';raw=b'synthetic runtime fixture';digest=hashlib.sha256(raw).hexdigest();(build/'collector-runtime.tar.gz').write_bytes(raw)
   receipt={'helper_commit':M['COMPATIBLE_BUILD_HELPER'],'source_commit':M['BASELINE'],'lockfile_sha256':M['LOCK'],'npm_ignore_scripts':True,'artifact_sha256':digest,'runtime_verification':{'required_edges_verified':True,'probe':{'real_http_module_loaded':True,'backend_undici_version':'8.11.2'}}};original=json.dumps(receipt).encode();(build/'build-result.json').write_bytes(original)
   g=M['main'].__globals__;out=io.StringIO();answers=[digest,'fixture_db','65439','fixture_app','fixture-deploy',answer]
   with patch.dict(g,{'TARGET':target,'trusted':lambda p:None}),patch.object(g['os'],'geteuid',return_value=0),patch.dict(os.environ,{'SUDO_UID':str(os.getuid())}),patch.object(g['sys'],'argv',['configure.py','--helper-commit','f'*40,'--build-dir',str(build)]),patch.object(g['sys'].stdin,'isatty',return_value=True),patch.object(g['pwd'],'getpwnam',return_value=types.SimpleNamespace(pw_uid=1001)),patch.object(g['subprocess'],'run',return_value=types.SimpleNamespace(stdout='fixture-deploy')),patch('builtins.input',side_effect=answers),contextlib.redirect_stdout(out):
    if answer=='CONFIRM':M['main']()
    else:
     with self.assertRaisesRegex(M['Refused'],'confirmation_cancelled'):M['main']()
   self.assertEqual((build/'build-result.json').read_bytes(),original);self.assertEqual((build/'collector-runtime.tar.gz').read_bytes(),raw)
   if answer=='CONFIRM':
    self.assertEqual((target/'collector-runtime.tar.gz').read_bytes(),raw);self.assertIn('original build helper: '+M['COMPATIBLE_BUILD_HELPER'],out.getvalue());self.assertTrue((target/'runtime_check.py').is_file())
   else:self.assertFalse(target.exists())
 def test_main_cancel_leaves_target_absent_and_original_receipt_unchanged(self):self.run_main_fixture('STOP')
 def test_main_confirm_reuses_original_artifact_and_receipt(self):self.run_main_fixture('CONFIRM')
if __name__=='__main__':unittest.main(verbosity=2)

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { test } from "node:test";
const root = path.resolve(import.meta.dirname, "../..");

test("forced entry rejects shell/SFTP/forwarding requests and validates bounded immutable uploads", () => {
  const result = spawnSync("python3", ["-B", "-c", `
import importlib.util, tempfile, pathlib, io, hashlib
spec=importlib.util.spec_from_file_location('gateway','deploy/native/ssh-gateway.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m.parse('verify')==['verify']
sha='a'*40; digest=hashlib.sha256(b'archive').hexdigest()
assert m.parse('upload '+sha+' '+digest)[0]=='upload'
assert m.parse('rollback '+sha)[0]=='rollback'
for bad in ('', 'sh', 'bash -c id', 'verify;id', 'verify\\n', 'scp -t /tmp/x', 'internal-sftp', 'deploy ../../x '+digest, 'verify extra'):
    try: m.parse(bad)
    except ValueError: pass
    else: raise AssertionError('command accepted')
with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d); (p/'incoming').mkdir()
    m.upload(p,sha,digest,io.BytesIO(b'archive'))
    assert (p/'incoming'/ (sha+'.tar.gz')).read_bytes()==b'archive'
    for content in (b'archive', b'bad'):
        try: m.upload(p,sha,digest,io.BytesIO(content))
        except ValueError: pass
        else: raise AssertionError('overwrite accepted')
    m.LIMIT=4
    try: m.upload(p,'b'*40,digest,io.BytesIO(b'archive'))
    except ValueError: pass
    else: raise AssertionError('size limit not enforced')
    assert not list((p/'incoming').glob('.upload-*'))
`], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("bootstrap uses only public key, root-owned entry/home and exact sudo command (all account operations mocked)", () => {
  const result = spawnSync("python3", ["-B", "-c", `
import importlib.util, tempfile, pathlib, base64, struct, types, os
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('boot','deploy/native/bootstrap-access.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
raw=struct.pack('>I',11)+b'ssh-ed25519'+struct.pack('>I',32)+bytes(32)
key=m.public_key('ssh-ed25519 '+base64.b64encode(raw).decode())
line=m.authorized_key(key)
assert line.startswith('restrict,command="/usr/bin/python3 -I /opt/aifinance/bin/ssh-gateway.py" ')
for bad in ('PRIVATE KEY', 'command="id" '+key, key+'\\n'+key):
    try: m.public_key(bad)
    except ValueError: pass
    else: raise AssertionError('unsafe key accepted')
assert '*' not in m.SUDO_RULE and 'ALL=(root) NOPASSWD: /usr/bin/systemctl restart aifinance-preview-api.service aifinance-preview-web.service' in m.SUDO_RULE
with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d); m.ROOT=p/'opt'; m.HOME=p/'home'; m.SUDO=p/'sudoers'
    calls=[]; owners=[]
    def account(name): return types.SimpleNamespace(pw_uid=1001 if name=='aifinance' else 1002,pw_gid=1001 if name=='aifinance' else 1002)
    with patch.object(m.subprocess,'run',side_effect=lambda args,**kw: calls.append(args)),patch.object(m.pwd,'getpwnam',side_effect=account),patch.object(m.os,'chown',side_effect=lambda *args: owners.append(args)),patch.object(m.shutil,'which',side_effect=lambda n:'/usr/sbin/'+n):
        m.provision(pathlib.Path('deploy/native'),key)
    assert len([c for c in calls if c[0]=='useradd'])==2
    assert not any('restart' in c for c in calls)
    assert not (m.ROOT/'shared/native-ready').exists()
    assert not (m.ROOT/'shared/schema.sha256').exists()
    assert not any('/bin' in str(x[0]) or '/home' in str(x[0]) for x in owners)
    assert (m.HOME/'.ssh/authorized_keys').read_text()==line
    try: m.provision(pathlib.Path('deploy/native'),key)
    except ValueError: pass
    else: raise AssertionError('existing installation overwritten')
`], { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

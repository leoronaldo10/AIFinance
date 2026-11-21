#!/usr/bin/python3
"""Passive fixed-unit observer: no DB, credentials, network, logs or unit mutations."""
import datetime,json,os,pathlib,stat,subprocess,tempfile,threading,signal
UNIT='aifinance-native-resident.service'
DIRECTORY=pathlib.Path('/run/aifinance-collection-observer')
COMMAND=['/usr/bin/systemctl','show',UNIT,'--property=LoadState,ActiveState,UnitFileState','--no-pager']
def snapshot(run=subprocess.run,now=None):
    out={'format':1,'unit':UNIT,'observedAt':(now or datetime.datetime.now(datetime.timezone.utc)).isoformat(),'activeState':'unknown','loadState':'unknown','unitFileState':'unknown'}
    try:
        r=run(COMMAND,capture_output=True,text=True,timeout=5,check=False,env={'PATH':'/usr/bin:/bin','LANG':'C'},cwd='/')
        if r.returncode!=0 or len(r.stdout)>1024:return out
        fields=dict(line.split('=',1)for line in r.stdout.splitlines()if'='in line)
        for key,allowed in [('ActiveState',{'active','inactive','failed','activating','deactivating','reloading'}),('LoadState',{'loaded','not-found','masked','error'}),('UnitFileState',{'enabled','disabled','static','masked'})]:
            if fields.get(key)in allowed:out[key[0].lower()+key[1:]]=fields[key]
    except Exception:pass
    return out

def write_snapshot(value,directory=DIRECTORY):
    s=directory.lstat()
    if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.getuid()or s.st_mode&0o022:raise ValueError('unsafe_observer_directory')
    fd,name=tempfile.mkstemp(prefix='.status-',dir=directory)
    try:
        with os.fdopen(fd,'w')as f:
            json.dump(value,f,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
        os.chmod(name,0o640)
        os.replace(name,directory/'status.json')
        d=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.lexists(name):os.unlink(name)

def main():
    stop=threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    while not stop.is_set():
        write_snapshot(snapshot())
        stop.wait(30)
if __name__=='__main__':main()

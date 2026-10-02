#!/usr/bin/bash
# One approved, bounded acceptance run. Run only from a reviewed root-owned file.
# Never starts DB/API/web, changes firewalld, enables units, or removes guard rules.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME
umask 077
[[ $# == 0 && $EUID == 0 ]] || { echo 'Root and no arguments required' >&2; exit 1; }
readonly EVIDENCE=/run/aifinance-egress-acceptance
readonly PROBE=/opt/aifinance/bin/isolation-probe.py
readonly GUARD=/opt/aifinance/bin/egress-guard.py
readonly GUARD_UNIT=aifinance-preview-egress.service
readonly LISTENER=aifinance-isolation-listener.service
readonly UNITS=("$LISTENER" aifinance-isolation-before.service aifinance-isolation-after.service
                aifinance-isolation-api-budget.service aifinance-isolation-web-budget.service
                aifinance-isolation-control.service)
created4=0 created6=0 success=0 cleanup_failed=0
attempted=()
fail() { echo "STOP: $*" >&2; exit 1; }
field() {
  local value
  value=$(/usr/bin/systemctl show "$1" --property="$2" --value) || return 1
  printf '%s\n' "$value"
}
port8000() { /usr/sbin/ss -H -lntpe 'sport = :8000' | /usr/bin/awk '{$2=""; $3=""; print}' | /usr/bin/sort; }
port48173() { /usr/sbin/ss -H -antup '( sport = :48173 or dport = :48173 )'; }

# Hash and path checks happen before importing the already-installed guard helper.
PREFLIGHT=$(/usr/bin/python3 -I -B - <<'PY'
import hashlib, importlib.util, os, stat
from pathlib import Path
expected = {
 '/opt/aifinance/bin/isolation-probe.py': '46350936233416c282bd8941c063cdffb09bf138e5f4e29158afc236dfd8ac7e',
 '/opt/aifinance/bin/egress-guard.py': '5c407c3916e1f44441f0a3962ea802d148084c281426ec0f809e9ad542913367',
 '/etc/systemd/system/aifinance-preview-egress.service': 'e89d001be5bb1929553c1b219759a9f123da6484229af3264e954f072047773e',
}
for name, digest in expected.items():
 p = Path(name)
 for q in (p,) + tuple(p.parents):
  s=q.lstat()
  if s.st_uid != 0 or s.st_mode & 0o022 or not (stat.S_ISREG(s.st_mode) if q==p else stat.S_ISDIR(s.st_mode)):
   raise SystemExit('Untrusted installed helper path')
 if hashlib.sha256(p.read_bytes()).hexdigest() != digest:
  raise SystemExit('Installed helper differs from reviewed fixed hashes')
for name in ('/run/aifinance-egress-acceptance', '/run/aifinance-preview-egress/receipt.json'):
 p=Path(name)
 if p.exists() or p.is_symlink(): raise SystemExit('Existing acceptance directory or guard receipt')
p=Path('/run'); s=p.lstat()
if not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_mode & 0o022: raise SystemExit('Untrusted /run')
spec=importlib.util.spec_from_file_location('guard', '/opt/aifinance/bin/egress-guard.py')
g=importlib.util.module_from_spec(spec); spec.loader.exec_module(g)
uid=g.app_uid(); g.no_app_processes(uid)
print(uid, os.urandom(16).hex())
PY
)
read -r APP_UID RUN_TOKEN <<<"$PREFLIGHT"
[[ $APP_UID =~ ^[1-9][0-9]*$ && $RUN_TOKEN =~ ^[0-9a-f]{32}$ ]] || fail 'Invalid identity preflight'
readonly APP_UID RUN_TOKEN
readonly OWNER="aifinance-egress-acceptance:$RUN_TOKEN"
for unit in "${UNITS[@]}"; do
  [[ $(field "$unit" LoadState) == not-found ]] || fail "Existing probe unit: $unit"
done
for unit in aifinance-preview-api.service aifinance-preview-web.service "$GUARD_UNIT"; do
  [[ $(field "$unit" ActiveState) == inactive ]] || fail "Preview/guard unit not inactive: $unit"
done
[[ $(field "$GUARD_UNIT" FragmentPath) == /etc/systemd/system/aifinance-preview-egress.service ]] || fail 'Unexpected guard unit source'
dropins=$(field "$GUARD_UNIT" DropInPaths)
stale=$(field "$GUARD_UNIT" NeedDaemonReload)
[[ -z $dropins && $stale == no ]] || fail 'Guard unit override or stale manager configuration'
[[ $(field firewalld.service ActiveState) == active ]] || fail 'firewalld is not active'
ports=$(port48173)
[[ -z $ports ]] || fail 'Port 48173 already used'
/usr/sbin/nft --json list tables | /usr/bin/python3 -I -B -c '
import json,sys
x=json.load(sys.stdin)
for obj in x["nftables"]:
 if "metainfo" in obj: continue
 t=obj["table"]
 if t["family"]=="inet" and t["name"] in ("aifinance_preview_probe","aifinance_preview_egress_v1"):
  raise SystemExit("Existing probe or guard nft table")
'
# Reject either address anywhere on this host. No query failure means absence.
addresses=$(/usr/sbin/ip -o address show)
[[ $addresses != *'192.0.2.254/'* && $addresses != *'2001:db8:ffff::254/'* ]] || fail 'Test address already exists'
/usr/bin/mkdir -m 0700 "$EVIDENCE"

cleanup() {
  local rc=$? unit load desc state sockets
  trap - EXIT INT TERM HUP
  set +e
  for unit in "${attempted[@]}"; do
    /usr/bin/systemctl show "$unit" --property=LoadState,Description,ActiveState,SubState,MainPID,ControlGroup >"$EVIDENCE/$unit.final.txt" 2>&1
    load=$(field "$unit" LoadState)
    if [[ $? != 0 ]]; then cleanup_failed=1; continue; fi
    [[ $load == not-found ]] && continue
    desc=$(field "$unit" Description)
    if [[ $? != 0 || $desc != "$OWNER" ]]; then
      echo "Cleanup blocked: uncertain ownership of $unit" >&2; cleanup_failed=1; continue
    fi
    /usr/bin/journalctl -u "$unit" --no-pager -n 30 -o cat >"$EVIDENCE/$unit.journal.txt" 2>&1
    /usr/bin/systemctl stop "$unit" || cleanup_failed=1
    load=$(field "$unit" LoadState)
    if [[ $? != 0 ]]; then cleanup_failed=1; continue; fi
    [[ $load == not-found ]] && continue
    state=$(field "$unit" ActiveState)
    if [[ $? != 0 || ( $state != inactive && $state != failed ) ]]; then cleanup_failed=1; fi
    [[ $(field "$unit" MainPID) == 0 ]] || cleanup_failed=1
    # Retain failed transient units and all evidence; no reset-failed is automatic.
  done
  # Established/TIME_WAIT probe sockets may remain; only listeners block removal.
  sockets=$(/usr/sbin/ss -H -lntp 'sport = :48173')
  [[ $? == 0 && -z $sockets ]] || cleanup_failed=1
  if (( cleanup_failed == 0 )); then
    if (( created6 )); then /usr/sbin/ip -6 address del 2001:db8:ffff::254/128 dev lo || cleanup_failed=1; fi
    if (( created4 )); then /usr/sbin/ip -4 address del 192.0.2.254/32 dev lo || cleanup_failed=1; fi
  else
    echo 'Probe stop uncertain; leaving added addresses for explicit administrator cleanup' >&2
  fi
  /usr/sbin/ip -o address show >"$EVIDENCE/addresses.after.txt" 2>&1 || cleanup_failed=1
  if (( created4 )) && /usr/bin/grep -Fq '192.0.2.254/' "$EVIDENCE/addresses.after.txt"; then cleanup_failed=1; fi
  if (( created6 )) && /usr/bin/grep -Fq '2001:db8:ffff::254/' "$EVIDENCE/addresses.after.txt"; then cleanup_failed=1; fi
  port8000 >"$EVIDENCE/8000.after.txt" || cleanup_failed=1
  /usr/bin/cmp -s "$EVIDENCE/8000.before.txt" "$EVIDENCE/8000.after.txt" || cleanup_failed=1
  /usr/bin/systemctl show firewalld.service --property=ActiveState,SubState,MainPID >"$EVIDENCE/firewalld.after.txt" 2>&1
  /usr/bin/cmp -s "$EVIDENCE/firewalld.before.txt" "$EVIDENCE/firewalld.after.txt" || cleanup_failed=1
  /usr/bin/systemctl show "$GUARD_UNIT" --property=ActiveState,SubState,Result >"$EVIDENCE/guard.final.txt" 2>&1
  if (( success == 1 )); then
    /usr/bin/python3 -I -B "$GUARD" verify >"$EVIDENCE/guard.after-cleanup.json" || cleanup_failed=1
  fi
  # Deliberately no guard stop/delete, even after partial loading or failed verify.
  if (( rc == 0 && success == 1 && cleanup_failed == 0 )); then
    echo 'PASS: dual-stack probe and 64/320/256 MiB checks passed; temporary probes/addresses cleaned; formal guard retained.'
    echo "Evidence: $EVIDENCE (root only). Old 8000 socket/PID unchanged; HTTP health was not tested. This does not accept final application units or start the application."
    printf 'probe_passed=true\napplication_accepted=false\n' >"$EVIDENCE/result.txt"
    exit 0
  fi
  printf 'probe_passed=false\napplication_accepted=false\ncleanup_failed=%s\n' "$cleanup_failed" >"$EVIDENCE/result.txt"
  echo "FAILED/INCONCLUSIVE; no application started. Keep guard/receipt and inspect root-only evidence: $EVIDENCE" >&2
  exit 1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

port8000 >"$EVIDENCE/8000.before.txt"
[[ -s "$EVIDENCE/8000.before.txt" ]] || fail 'Expected old 8000 listener is absent'
/usr/bin/grep -Eq 'pid=[0-9]+' "$EVIDENCE/8000.before.txt" || fail 'Cannot identify old 8000 listener PID'
if /usr/bin/grep -Eq "(^|[[:space:]])uid:$APP_UID([[:space:]]|$)" "$EVIDENCE/8000.before.txt"; then fail 'Old 8000 socket belongs to app UID'; fi
/usr/bin/systemctl show firewalld.service --property=ActiveState,SubState,MainPID >"$EVIDENCE/firewalld.before.txt"
/usr/sbin/ip -o address show >"$EVIDENCE/addresses.before.txt"
/usr/sbin/ip -4 route show table all >"$EVIDENCE/routes4.before.txt"
/usr/sbin/ip -6 route show table all >"$EVIDENCE/routes6.before.txt"
/usr/bin/python3 -I -B - "$EVIDENCE" <<'PY'
import ipaddress,sys
from pathlib import Path
for family,target in ((4,'192.0.2.254'),(6,'2001:db8:ffff::254')):
 for line in (Path(sys.argv[1])/('routes%d.before.txt'%family)).read_text().splitlines():
  words=line.split()
  if words and words[0] in ('local','broadcast','unreachable','blackhole','prohibit','throw','nat'): words=words[1:]
  if not words or words[0]=='default': continue
  try: net=ipaddress.ip_network(words[0],strict=False)
  except ValueError: continue
  if ipaddress.ip_address(target) in net: raise SystemExit('Test address is already covered by a non-default route')
PY
/usr/sbin/nft --version >"$EVIDENCE/nft.version.txt"
/usr/bin/systemctl --version >"$EVIDENCE/systemd.version.txt"
/usr/bin/cat /proc/meminfo >"$EVIDENCE/meminfo.before.txt"
/usr/sbin/ip -4 address add 192.0.2.254/32 dev lo
created4=1
/usr/sbin/ip -6 address add 2001:db8:ffff::254/128 dev lo
created6=1
# DAD is asynchronous. Inspect only our address; never disable DAD or skip IPv6.
for attempt in {1..11}; do
  v6=$(/usr/sbin/ip -o -6 address show dev lo to 2001:db8:ffff::254/128)
  printf '%s\n' "$v6" >"$EVIDENCE/ipv6-ready.$attempt.txt"
  [[ $v6 == *'2001:db8:ffff::254/128'* ]] || fail 'IPv6 test address disappeared'
  [[ $v6 != *dadfailed* ]] || fail 'IPv6 duplicate address detection failed'
  [[ $v6 == *tentative* ]] || break
  (( attempt < 11 )) || fail 'IPv6 address remained tentative after 10 seconds'
  /usr/bin/sleep 1
done

props=(-p "Description=$OWNER" -p MemoryAccounting=yes -p TasksMax=16 -p CPUQuota=10%
       -p RuntimeMaxSec=190 -p TimeoutStopSec=5 -p KillMode=control-group -p Restart=no
       -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p AmbientCapabilities=
       -p PrivateTmp=yes -p ProtectSystem=strict -p ProtectHome=yes
       -p 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' -p LimitNOFILE=64 -p LimitCORE=0 -p UMask=0077)
attempted+=("$LISTENER")
/usr/bin/systemd-run --quiet --unit="$LISTENER" "${props[@]}" -p MemoryLimit=64M -p User=root -p Group=root \
  /usr/bin/python3 -I -B "$PROBE" serve >"$EVIDENCE/listener.start.txt" 2>&1
started=$SECONDS
live() {
  (( SECONDS - started < 160 )) || fail 'Listener acceptance window expired'
  [[ $(field "$LISTENER" ActiveState) == active && $(field "$LISTENER" Description) == "$OWNER" ]] || fail 'Listener stopped or changed'
}
for attempt in {1..10}; do
  live
  pid=$(field "$LISTENER" MainPID)
  /usr/sbin/ss -H -lntp 'sport = :48173' >"$EVIDENCE/listeners.txt"
  if /usr/bin/python3 -I -B - "$EVIDENCE/listeners.txt" "$pid" <<'PY'
import re,sys
from pathlib import Path
expected={'127.0.0.1','::1','192.0.2.254','2001:db8:ffff::254'}
seen=set(); lines=Path(sys.argv[1]).read_text().splitlines()
for line in lines:
 fields=line.split()
 if len(fields)<5 or not re.search(r'\bpid='+re.escape(sys.argv[2])+r'\b',line): raise SystemExit(1)
 host,port=fields[3].rsplit(':',1)
 if port!='48173': raise SystemExit(1)
 seen.add(host.strip('[]'))
raise SystemExit(0 if len(lines)==4 and seen==expected and int(sys.argv[2])>0 else 1)
PY
  then break; fi
  (( attempt < 10 )) || fail 'Four fixed listeners did not become ready'
  /usr/bin/sleep 1
done
/usr/bin/journalctl -u "$LISTENER" --no-pager -n 10 -o cat >"$EVIDENCE/listener.ready.txt"

run_probe() {
  local unit=$1 mode=$2 memory=$3 account=$4 label=$5
  live
  [[ $(field "$unit" LoadState) == not-found ]] || fail "Probe name changed before use: $unit"
  attempted+=("$unit")
  /usr/bin/systemd-run --quiet --wait --pipe --unit="$unit" "${props[@]}" -p "MemoryLimit=${memory}M" \
    -p "User=$account" -p "Group=$account" /usr/bin/python3 -I -B "$PROBE" "$mode" --memory-limit-mib "$memory" \
    >"$EVIDENCE/$label.json" 2>"$EVIDENCE/$label.stderr.txt"
  live
}
run_probe aifinance-isolation-before.service baseline 64 aifinance baseline
/usr/bin/systemctl start "$GUARD_UNIT" >"$EVIDENCE/guard.start.txt" 2>&1
/usr/bin/python3 -I -B "$GUARD" verify >"$EVIDENCE/guard.before.json"
run_probe aifinance-isolation-after.service guarded 64 aifinance guarded64
/usr/bin/python3 -I -B "$GUARD" verify >"$EVIDENCE/guard.after64.json"
run_probe aifinance-isolation-api-budget.service guarded 320 aifinance guarded320
/usr/bin/python3 -I -B "$GUARD" verify >"$EVIDENCE/guard.after320.json"
run_probe aifinance-isolation-web-budget.service guarded 256 aifinance guarded256
/usr/bin/python3 -I -B "$GUARD" verify >"$EVIDENCE/guard.after256.json"
run_probe aifinance-isolation-control.service control 64 root control
live
/usr/bin/python3 -I -B - "$EVIDENCE" "$APP_UID" <<'PY'
# Validate only outputs of the two pinned helpers, not a general-purpose checker.
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); uid=int(sys.argv[2])
def load(name): return json.loads((root/(name+'.json')).read_text())
for label,mode,memory,who in [('baseline','baseline',64,uid),('guarded64','guarded',64,uid),('guarded320','guarded',320,uid),('guarded256','guarded',256,uid),('control','control',64,0)]:
 x=load(label)
 if x['mode']!=mode or x['expectations_matched'] is not True or x['memory']['uid']!=who or x['memory']['memory.limit_in_bytes']!=memory*1024*1024:
  raise SystemExit('Probe identity/result/memory mismatch: '+label)
 if len(x['network'])!=4 or any(n['expectation_matched'] is not True for n in x['network']): raise SystemExit('Incomplete network evidence')
previous=load('guard.before')
for label in ('guard.after64','guard.after320','guard.after256'):
 x=load(label)
 if x['guard_loaded'] is not True or previous['guard_loaded'] is not True or x['uid']!=uid or previous['uid']!=uid or x['table']!='aifinance_preview_egress_v1' or x['table']!=previous['table'] or x['handle']!=previous['handle'] or set(x['counters'])!=set(previous['counters']):
  raise SystemExit('Guard changed during probe')
 for suffix in (':deny-v4',':deny-v6'):
  keys=[k for k in x['counters'] if k.endswith(suffix)]
  if len(keys)!=1 or x['counters'][keys[0]]['packets']<=previous['counters'][keys[0]]['packets']:
   raise SystemExit('Missing per-family reject counter increase: '+label+suffix)
 previous=x
print('Pinned helper results and per-run dual-stack counter deltas agree')
PY
success=1

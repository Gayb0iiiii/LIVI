import gzip,hashlib,json,os,subprocess,tempfile
from pathlib import Path
wrapper=Path(__file__).parent.joinpath('lyLink.sh').read_text()
source=Path(__file__).parent.joinpath('ax520-start.sh').read_text()
def sha(b):return hashlib.sha256(b).hexdigest()
for failed in (False,True):
 with tempfile.TemporaryDirectory() as temp:
  root=Path(temp);ram=root/'ram';ram.mkdir();disk=root/'disk';(disk/'payload').mkdir(parents=True);proc=root/'proc';proc.mkdir();bin=root/'bin';bin.mkdir()
  fixtures={
   'bridge-trial':b'#!/bin/sh\necho "bridge" >> "$FIXTURE_LOG"\nmkdir "$FIXTURE_ROOT/ram/ax520-observer-trial-Ab12Cd"\nprintf "observer loaded\\nobserver selected\\n" > "$FIXTURE_ROOT/ram/ax520-observer-trial-Ab12Cd/status"\necho "watchdog=300 status=/tmp/ax520-observer-trial-Ab12Cd/status"\n',
   'bridge.so':b'mock shim',
   'adb-trial':b'#!/bin/sh\necho "usb" >> "$FIXTURE_LOG"\necho adb_usb_ready > "$2/status"\n',
   'libax520-ep0-audit.so':b'mock audit'}
  hashes={'bridge-trial':'d153b306c18ee6a6cbd1e0047e6589d578062582b5cbe5c26514e19a720a339b','bridge.so':'8e0800cb7eacad871813f126510941ebb7d45b69fab84245c3c130e728350d0e','adb-trial':'4c12528ad37c22be664f3330aaf56f5bba394162661859bed4d40811b3772768','libax520-ep0-audit.so':'b6366dba53601046a50e311be820e62d9856e5519c9cf81607b41c447761bfc7'}
  text=source
  for name,data in fixtures.items():
   (disk/'payload'/f'{name}.gz').write_bytes(gzip.compress(data,mtime=0));text=text.replace(hashes[name],sha(data))
  if failed:(disk/'payload/bridge.so.gz').write_bytes(gzip.compress(b'corrupt',mtime=0))
  lines=[]
  for line in text.splitlines():
   if line.startswith('check /mnt/customer/') or line.startswith('check /lib/'):
    path,digest=line.split()[1:];p=root/path.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixed stock');line=f'check {str(p).replace(chr(47)+"tmp"+chr(47), "__FIXTURE_TMP__/")} {sha(b"fixed stock")}'
   lines.append(line)
  text='\n'.join(lines)+'\n'
  text=text.replace('/tmp/',str(ram)+'/').replace('/mnt/UDISK/app',str(disk)).replace('/proc/',str(proc)+'/').replace('__FIXTURE_TMP__/','/tmp/')
  # Fake guard acknowledgment uses the same generated fixture location.
  data=fixtures['bridge-trial'].replace(b'/tmp/ax520-observer-trial-',(str(ram)+'/ax520-observer-trial-').encode())
  (disk/'payload/bridge-trial.gz').write_bytes(gzip.compress(data,mtime=0));text=text.replace(sha(fixtures['bridge-trial']),sha(data))
  (proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text('fixtureboot')
  for pid,parent in ((100,1),(101,100)):
   (proc/str(pid)).mkdir();(proc/str(pid)/'stat').write_text(f'{pid} (lylinkapp) S {parent} 100 0\n')
  (bin/'pidof').write_text('#!/bin/sh\necho 100 101\n');(bin/'pidof').chmod(0o700)
  log=root/'log';env=os.environ|{'PATH':str(bin)+':'+os.environ['PATH'],'FIXTURE_ROOT':str(root),'FIXTURE_LOG':str(log)}
  script=root/'start.sh';script.write_text(text)
  result=subprocess.run(['/bin/sh',str(script)],env=env,capture_output=True,text=True,timeout=8)
  if failed:
   assert result.returncode and not log.exists() and not (ram/'livi-ax520-managed.boot').exists(),result.stdout+result.stderr
  else:
   assert result.returncode==0,result.stdout+result.stderr
   assert log.read_text()=='bridge\nusb\n'
   assert (ram/'livi-ax520-managed.boot').read_text().startswith('AX520_BOOT_V1\n')
   print('PASS stock bootstrap decompresses, verifies, starts bridge before USB and publishes receipt')
print('PASS corrupt helper rejected before either launcher runs')

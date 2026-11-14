import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time
import unittest

BASE=Path(__file__).resolve().parent
class ManagedUsbTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(BASE/'usb.c').read_text()
  # Exercise the actual CLI, daemon lifecycle, pid tracking and descendant
  # cleanup. Only hardware setup/restoration and fixture ownership are replaced.
  for old,new in [
   ('static int preflight(void){','static int unused_preflight(void){'),
   ('static void setup_worker(pid_t supervisor_pid){','static void unused_setup_worker(pid_t supervisor_pid){'),
   ('static int restore(void){','static int unused_restore(void){'),
   ('now_ms()+90000','now_ms()+150'),
   ('"/tmp/ax520-adb-trial.lock"','"/tmp/ax520-managed-usb-fixture.lock"')]:
   assert source.count(old)==1,(old,source.count(old))
   source=source.replace(old,new)
  identity_define='#define MANAGED_IDENTITY_EXISTS\n' if 'static struct identity managed_adb;' in source else ''
  prefix=identity_define+r'''
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
static uid_t fixture_uid(void){return 0;}
static int fixture_fstat(int fd,struct stat *s){int r=fstat(fd,s);if(!r)s->st_uid=0;return r;}
static int fixture_lstat(const char *p,struct stat *s){int r=lstat(p,s);if(!r)s->st_uid=0;return r;}
#define getuid fixture_uid
#define geteuid fixture_uid
#define fstat fixture_fstat
#define lstat fixture_lstat
#define main original_main
static int preflight(void);
static void setup_worker(pid_t parent);
static int restore(void);
'''
  suffix=r'''
#undef main
static int preflight(void){return 1;}
static void setup_worker(pid_t parent){
 if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||setpgid(0,0))_exit(20);
 signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);
 note("fixture_worker_alive");
 dprintf(status_fd,"fixture_worker_pid %ld\n",(long)getpid());fsync(status_fd);
 for(;;)pause();
}
static int restore(void){note("fixture_restore_once");return 0;}

#ifndef MANAGED_IDENTITY_EXISTS
static struct identity managed_adb;
#endif
static int open_listener(int port){
 int s=socket(AF_INET,SOCK_STREAM,0),opt=1;
 struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_port=htons((unsigned short)port);addr.sin_addr.s_addr=htonl(INADDR_ANY);
 if(s<0||setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt)||bind(s,(struct sockaddr*)&addr,sizeof addr)||listen(s,1))return -1;
 return s;
}
int main(int argc,char **argv){
 if(argc==5&&!strcmp(argv[1],"--listener-case")){
  managed_usb=atoi(argv[2]);int mine=atoi(argv[3]),port=atoi(argv[4]);
  if(listeners_read(&initial_listeners)||process(getpid(),&managed_adb))return 2;
  int sock=-1,pipefd[2];pid_t child=-1;
  if(mine==1||mine==2){sock=open_listener(port);if(sock<0)return 2;}
  else{
   if(pipe(pipefd))return 2;
   child=fork();
   if(child==0){close(pipefd[0]);sock=open_listener(port);char ok=sock>=0?'Y':'N';if(write(pipefd[1],&ok,1)!=1)_exit(3);close(pipefd[1]);for(;;)pause();}
   close(pipefd[1]);char ok=0;if(read(pipefd[0],&ok,1)!=1||ok!='Y')return 2;close(pipefd[0]);
  }
  if(mine==2)managed_adb.start++;
  int ok=mine==3?listeners_unchanged():listeners_during_trial();
  if(sock>=0)close(sock);
  if(child>0){kill(child,SIGTERM);waitpid(child,NULL,0);}
  printf("%d\n",ok);return 0;
 }
 return original_main(argc,argv);
}
'''
  (BASE/'fixture.c.generated').write_text(prefix+source+suffix)
  subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-O1','-x','c',str(BASE/'fixture.c.generated'),'-o',str(BASE/'fixture')],check=True,capture_output=True)
 def setUp(self):
  self.directory=Path('/tmp/ax520-adb-'+os.urandom(6).hex());self.directory.mkdir(mode=0o700);self.pid=None
 def launch(self,mode):
  result=subprocess.run([str(BASE/'fixture'),mode,str(self.directory)],capture_output=True,text=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.pid=int(re.search(r'ADB_WATCHDOG_PID=(\d+)',result.stdout).group(1))
  return self.directory/'status'
 def wait_restored(self,path):
  until=time.monotonic()+8
  while time.monotonic()<until:
   text=path.read_text()
   if 'result_restored_device_state' in text:return text
   time.sleep(.02)
  self.fail(path.read_text())
 def test_finite_mode_still_expires_and_restores(self):
  status=self.launch('--run')
  text=self.wait_restored(status)
  self.assertEqual(text.count('fixture_restore_once'),1)
 def test_managed_mode_survives_old_deadline_then_restores_on_term(self):
  status=self.launch('--managed')
  time.sleep(.65)
  text=status.read_text()
  self.assertIn('fixture_worker_alive',text)
  self.assertNotIn('restoration_started',text)
  os.kill(self.pid,signal.SIGTERM)
  text=self.wait_restored(status)
  self.assertEqual(text.count('fixture_restore_once'),1)
 def test_managed_worker_exit_still_restores_once(self):
  status=self.launch('--managed')
  until=time.monotonic()+2
  while time.monotonic()<until:
   match=re.search(r'fixture_worker_pid (\d+)',status.read_text())
   if match:break
   time.sleep(.01)
  self.assertIsNotNone(match)
  os.kill(int(match.group(1)),signal.SIGKILL)
  self.assertEqual(self.wait_restored(status).count('fixture_restore_once'),1)
 def listener_case(self,managed,owned,port):
  result=subprocess.run([str(BASE/'fixture'),'--listener-case',str(managed),str(owned),str(port)],capture_output=True,text=True,timeout=3)
  self.assertEqual(result.returncode,0,result.stderr)
  return result.stdout.strip()
 def test_managed_accepts_own_stock_adbd_listener(self):
  self.assertEqual(self.listener_case(1,1,5037),'1')
 def test_managed_rejects_reused_owner_identity(self):
  self.assertEqual(self.listener_case(1,2,5037),'0')
 def test_managed_rejects_own_unexpected_listener(self):
  self.assertEqual(self.listener_case(1,1,15001),'0')
 def test_managed_ignores_unrelated_stock_listener(self):
  self.assertEqual(self.listener_case(1,0,15001),'1')
 def test_managed_ignores_unrelated_stock_5555(self):
  self.assertEqual(self.listener_case(1,0,5555),'1')
 def test_managed_cleanup_ignores_replacement_stock_5037(self):
  self.assertEqual(self.listener_case(1,3,5037),'1')
 def test_finite_mode_retains_global_listener_policy(self):
  self.assertEqual(self.listener_case(0,0,15001),'0')
 def tearDown(self):
  if self.pid:
   try:os.kill(self.pid,signal.SIGTERM)
   except ProcessLookupError:pass
  # Retain test evidence; never remove another run's global lock.
if __name__=='__main__':unittest.main()

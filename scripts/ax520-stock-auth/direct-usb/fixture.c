#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define TARGET "/tmp/ax520-ep0-audit-target"
#define OTHER "/tmp/ax520-ep0-audit-other"
#define EP1 "/tmp/ax520-ep0-audit-ep1"
#define EP2 "/tmp/ax520-ep0-audit-ep2"
extern int stock_open(const char *,int,...) __asm__("open");
#define open stock_open
int main(int argc,char **argv){
 assert(argc==3);int audit=atoi(argv[2]);
 umask(0);
 assert(getenv("LD_PRELOAD")==NULL&&getenv("AX520_EP0_AUDIT_FD")==NULL);
 assert(fcntl(audit,F_GETFD)&FD_CLOEXEC);unlink(TARGET);unlink(OTHER);
 errno=0;assert(access(TARGET,F_OK)==-1&&errno==ENOENT);
 if(!strcmp(argv[1],"ep-open")){
  unlink(EP1);unlink(EP2);errno=0;assert(open(EP1,O_RDONLY)==-1&&errno==ENOENT);errno=0;assert(open(EP2,O_RDONLY)==-1&&errno==ENOENT);
  int e=open(EP1,O_CREAT|O_RDWR,0600);assert(e>=0);assert(write(e,"UNTRACED_EP1_PAYLOAD",20)==20);assert(close(e)==0);unlink(EP1);return 0;
 }
 if(!strcmp(argv[1],"failure")){
  errno=0;assert(open(TARGET,O_RDONLY)==-1&&errno==ENOENT);
  int fd=open(TARGET,O_CREAT|O_RDONLY,0600);assert(fd>=0);errno=0;
  assert(write(fd,"SECRET_PAYLOAD",14)==-1&&errno==EBADF);assert(close(fd)==0);
 }else{
  errno=EALREADY;int fd=open(TARGET,O_CREAT|O_RDWR,0600);assert(fd>=0&&errno==EALREADY);
  if(!strcmp(argv[1],"dup")){
   int other=open(OTHER,O_CREAT|O_RDWR,0640);assert(other>=0);assert(dup2(other,fd)==fd);
   assert(write(fd,"UNTRACED_PAYLOAD",16)==16);assert(close(fd)==0);assert(close(other)==0);
  }else{
   int count=!strcmp(argv[1],"budget")?1000:1;
   for(int i=0;i<count;i++){errno=EALREADY;assert(write(fd,"SECRET_PAYLOAD",14)==14&&errno==EALREADY);}
   errno=EALREADY;assert(close(fd)==0&&errno==EALREADY);
   int other=open(OTHER,O_CREAT|O_RDWR,0640);assert(other==fd);struct stat st;assert(!fstat(other,&st)&&(st.st_mode&0777)==0640);
   assert(write(other,"UNTRACED_PAYLOAD",16)==16);assert(close(other)==0);
  }
 }
 unlink(TARGET);unlink(OTHER);return 0;
}

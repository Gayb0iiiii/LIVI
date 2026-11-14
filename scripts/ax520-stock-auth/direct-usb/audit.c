#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef AX520_EP0_PATH
#define AX520_EP0_PATH "/dev/usb-ffs/adb/ep0"
#endif
#ifndef AX520_EP1_PATH
#define AX520_EP1_PATH "/dev/usb-ffs/adb/ep1"
#endif
#ifndef AX520_EP2_PATH
#define AX520_EP2_PATH "/dev/usb-ffs/adb/ep2"
#endif
/* Numeric rows: operation fd count result errno. 0=ready,1=open,2=write,
 * 3=close,4=access. count is requested write bytes/access mode; for open,
 * count classifies the fixed ep0/ep1/ep2 path as0/1/2. Only ep0 is tracked.
 * errno is zero for success; actual caller errno is preserved separately.
 * Never inspect or format a write buffer. Never trace any other pathname.
 */
static int (*next_open)(const char *,int,...);
static ssize_t (*next_write)(int,const void *,size_t);
static int (*next_close)(int);
static int (*next_access)(const char *,int);
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static int ready;
static _Atomic int audit_fd=-1;
static pid_t audit_pid;
static dev_t audit_dev;
static ino_t audit_ino;
static unsigned records,bytes;
struct tracked {int used,fd;dev_t dev;ino_t ino;};
static struct tracked tracked[32];
static void unlock(void *unused){(void)unused;pthread_mutex_unlock(&lock);}
static int active(void){return ready&&audit_fd>=0&&getpid()==audit_pid;}
static int selected(const char *path){return path&&!strcmp(path,AX520_EP0_PATH);}
static int open_class(const char *path){
 if(!path)return -1;
 if(!strcmp(path,AX520_EP0_PATH))return 0;
 if(!strcmp(path,AX520_EP1_PATH))return 1;
 if(!strcmp(path,AX520_EP2_PATH))return 2;
 return -1;
}
static void forget(int fd){for(unsigned i=0;i<32;i++)if(tracked[i].used&&tracked[i].fd==fd)tracked[i].used=0;}
static int tracked_fd(int fd){
 for(unsigned i=0;i<32;i++)if(tracked[i].used&&tracked[i].fd==fd){
  struct stat s;
  if(!fstat(fd,&s)&&s.st_dev==tracked[i].dev&&s.st_ino==tracked[i].ino)return 1;
  tracked[i].used=0;
 }
 return 0;
}
static void remember(int fd){
 struct stat s;forget(fd);if(fd<0||fd==audit_fd||fstat(fd,&s))return;
 for(unsigned i=0;i<32;i++)if(!tracked[i].used){tracked[i]=(struct tracked){1,fd,s.st_dev,s.st_ino};return;}
}
static void emit(unsigned op,int fd,size_t count,long result,int saved_errno){
 if(!active()||records>=256)return;
 struct stat s;
 if(fstat(audit_fd,&s)||!S_ISREG(s.st_mode)||s.st_dev!=audit_dev||s.st_ino!=audit_ino||(s.st_mode&0777)!=0600){audit_fd=-1;return;}
 char line[96];int n=snprintf(line,sizeof line,"%u %d %lu %ld %d\n",op,fd,(unsigned long)count,result,result<0?saved_errno:0);
 if(n<=0||(size_t)n>=sizeof line||bytes+(unsigned)n>32768)return;
 records++;bytes+=(unsigned)n;
 /* The preopened descriptor is a private RAM regular file with O_APPEND.
  * Direct libc pointer avoids recursively entering our write wrapper. */
 ssize_t wrote=next_write(audit_fd,line,(size_t)n);
 if(wrote!=n)audit_fd=-1;
}
__attribute__((constructor)) static void initialize(void){
 int saved=errno;
 *(void **)(&next_open)=dlsym(RTLD_NEXT,"open");
 *(void **)(&next_write)=dlsym(RTLD_NEXT,"write");
 *(void **)(&next_close)=dlsym(RTLD_NEXT,"close");
 *(void **)(&next_access)=dlsym(RTLD_NEXT,"access");
 const char *value=getenv("AX520_EP0_AUDIT_FD");char *end=NULL;long fd=-1;
 if(value&&*value){errno=0;fd=strtol(value,&end,10);if(errno||*end||fd<3||fd>65535)fd=-1;}
 /* Native launcher refuses an existing preload and installs only this one. */
 unsetenv("LD_PRELOAD");unsetenv("AX520_EP0_AUDIT_FD");
 if(next_open&&next_write&&next_close&&next_access&&fd>=3){
  struct stat s;int flags=fcntl((int)fd,F_GETFL);
  if(!fstat((int)fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==geteuid()&&(s.st_mode&0777)==0600&&s.st_size==0&&s.st_nlink<=1&&
     flags>=0&&(flags&O_ACCMODE)!=O_RDONLY&&(flags&O_APPEND)&&fcntl((int)fd,F_SETFD,FD_CLOEXEC)==0){
   audit_fd=(int)fd;audit_dev=s.st_dev;audit_ino=s.st_ino;audit_pid=getpid();
  }
 }
 ready=1;emit(0,audit_fd,0,0,0);errno=saved;
}
/* Debian cross-compiler defaults may redirect the header name open to open64.
 * Export the exact symbol imported by this pinned stock binary explicitly. */
int audited_open(const char *path,int flags,...) __asm__("open");
int audited_open(const char *path,int flags,...){
 int before=errno;volatile mode_t mode=0;int has_mode=(flags&O_CREAT)!=0;
#ifdef O_TMPFILE
 has_mode=has_mode||((flags&O_TMPFILE)==O_TMPFILE);
#endif
 if(has_mode){va_list ap;va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}
 if(!next_open){errno=before;return (int)syscall(SYS_open,path,flags,mode);}
 int path_class=open_class(path);
 if(!active()||path_class<0){errno=before;return has_mode?next_open(path,flags,mode):next_open(path,flags);}
 int result,saved;pthread_mutex_lock(&lock);
 pthread_cleanup_push(unlock,NULL);
 errno=before;result=has_mode?next_open(path,flags,mode):next_open(path,flags);saved=errno;
 if(result>=0){if(path_class==0)remember(result);else forget(result);}
 emit(1,result,(size_t)path_class,result,saved);
 pthread_cleanup_pop(1);
 errno=saved;return result;
}
ssize_t write(int fd,const void *buffer,size_t count){
 int before=errno;
 if(!next_write){errno=before;return syscall(SYS_write,fd,buffer,count);}
 if(!active()||fd==audit_fd){errno=before;return next_write(fd,buffer,count);}
 pthread_mutex_lock(&lock);
 if(!tracked_fd(fd)){pthread_mutex_unlock(&lock);errno=before;return next_write(fd,buffer,count);}
 ssize_t result;int saved;
 pthread_cleanup_push(unlock,NULL);
 errno=before;result=next_write(fd,buffer,count);saved=errno;emit(2,fd,count,(long)result,saved);
 pthread_cleanup_pop(1);
 errno=saved;return result;
}
int close(int fd){
 int before=errno;
 if(!next_close){errno=before;return (int)syscall(SYS_close,fd);}
 if(!active()){errno=before;return next_close(fd);}
 pthread_mutex_lock(&lock);
 if(fd==audit_fd){audit_fd=-1;pthread_mutex_unlock(&lock);errno=before;return next_close(fd);}
 if(!tracked_fd(fd)){pthread_mutex_unlock(&lock);errno=before;return next_close(fd);}
 int result,saved;
 pthread_cleanup_push(unlock,NULL);
 errno=before;result=next_close(fd);saved=errno;forget(fd);emit(3,fd,0,result,saved);
 pthread_cleanup_pop(1);
 errno=saved;return result;
}
int access(const char *path,int mode){
 int before=errno;
 if(!next_access){errno=before;return (int)syscall(SYS_access,path,mode);}
 if(!active()||!selected(path)){errno=before;return next_access(path,mode);}
 int result,saved;pthread_mutex_lock(&lock);
 pthread_cleanup_push(unlock,NULL);
 errno=before;result=next_access(path,mode);saved=errno;emit(4,-1,(size_t)(unsigned)mode,result,saved);
 pthread_cleanup_pop(1);
 errno=saved;return result;
}

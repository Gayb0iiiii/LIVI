#define _GNU_SOURCE
/* RAM-only config1 ADB ownership: finite --run or explicit --managed.
 * Managed ownership ends on SIGTERM or worker failure; host loss alone does
 * not discard the management interface. Original PTP is restored on exit. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define G "/sys/kernel/config/usb_gadget/g1"
#define FF G "/functions/ffs.adb"
#define FL G "/configs/b.1/ffs.adb"
#ifndef PTPL
#define PTPL G "/configs/b.1/iphone_ptp.gs0"
#endif
#define MP "/dev/usb-ffs/adb"
#define UDC "b500000.usb"
#define ADB "/bin/adbd"
#define BB "/bin/busybox"
#define MAXPROC 2048
#define MAXLISTEN 128
static const char adb_sha[]="faddf86eafdb0d103d4570a1244a77e79f8e50c32104a3578012b2aeb1cecafc";
static const char loader_sha[]="39d3f7d7b34448c8c7026b6b3fe46218366700fc0c768c285796d6fcb2acd8b6";
static const char libc_sha[]="41954a9a9fd14d262eada61caf8de98749385e2dde1ed1fac488437a45efb69a";
static char directory[128];
static int status_fd=-1;
static int managed_usb;
static volatile sig_atomic_t interrupted;
struct identity {pid_t pid,parent,group;unsigned long long start;char state;};
static struct identity managed_adb;
struct shared {
    volatile sig_atomic_t function,rootdir,mountdir,mounted,link,unbind_attempted,ready,mutation,ptp_removed;
};
static struct shared *owned;
static const char *const fn[]={"iphone_audio.gs0","iphone_hid.gs0","iphone_ptp.gs0","iphone_vendor1.gs0","iphone_vendor2.gs0"};
static const unsigned cfg_masks[]={1U<<2,(1U<<0)|(1U<<1),(1U<<2)|(1U<<3),(1U<<2)|(1U<<3)|(1U<<4)};
static char original_ptp_link[256];
static unsigned config_mask(unsigned c){return c==0&&owned&&owned->ptp_removed?0:cfg_masks[c];}
static const char *const desc[]={"idVendor","idProduct","bDeviceClass","bDeviceSubClass","bDeviceProtocol","bcdUSB","bcdDevice"};
static const char *const expected_desc[]={"0x05ac","0x12a8","0x00","0x00","0x00","0x0200","0x0901"};
static char attrs[4][2][32];
struct listeners {unsigned n;char entries[MAXLISTEN][80];};
static struct listeners initial_listeners;
static char audit_library[180];
static const char audit_sha[]="b6366dba53601046a50e311be820e62d9856e5519c9cf81607b41c447761bfc7";

static int64_t now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void tick(void){struct timespec t={0,20000000};nanosleep(&t,NULL);}
static void signal_stop(int sig){(void)sig;interrupted=1;}
static void note(const char *s){if(status_fd>=0){dprintf(status_fd,"%s\n",s);fsync(status_fd);}}
static void errnote(const char *s){int e=errno;if(status_fd>=0){dprintf(status_fd,"%s %d\n",s,e);fsync(status_fd);}}
static int read_small(const char *path,char *s,size_t cap){
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    ssize_t n=read(fd,s,cap-1);int e=errno;close(fd);errno=e;
    if(n<0||(size_t)n>=cap-1){if(n>=0)errno=EOVERFLOW;return -1;}s[n]=0;return (int)n;
}
static int value(const char *path,char *s,size_t cap){int n=read_small(path,s,cap);if(n<0)return -1;while(n&&(s[n-1]=='\n'||s[n-1]=='\r'))s[--n]=0;return n;}
static int exact(const char *path,const char *expected){char s[128];return value(path,s,sizeof s)>=0&&!strcmp(s,expected);}
static int absent(const char *path){struct stat s;if(!lstat(path,&s))return 0;return errno==ENOENT;}
static int write_value(const char *path,const char *s){
    int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    size_t len=strlen(s);ssize_t n=write(fd,s,len);int e=errno;close(fd);errno=e;
    if(n!=(ssize_t)len){if(n>=0)errno=EIO;return -1;}return 0;
}
static int process(pid_t pid,struct identity *p){
    char path[64],buf[2048];snprintf(path,sizeof path,"/proc/%ld/stat",(long)pid);
    if(read_small(path,buf,sizeof buf)<0)return -1;
    char *s=strrchr(buf,')');if(!s||s[1]!=' '){errno=EINVAL;return -1;}s+=2;
    memset(p,0,sizeof *p);p->pid=pid;
    for(int field=3;field<=22;field++){
        char *end=strchr(s,' ');if(field<22&&!end){errno=EINVAL;return -1;}if(end)*end=0;
        if(field==3)p->state=*s;
        if(field==4||field==5||field==22){
            if(!isdigit((unsigned char)*s)){errno=EINVAL;return -1;}
            errno=0;char *tail;unsigned long long n=strtoull(s,&tail,10);
            if(errno||(*tail&&strcmp(tail,"\n"))||((field==4||field==5)&&n>INT_MAX)){errno=EINVAL;return -1;}
            if(field==4)p->parent=(pid_t)n;
            if(field==5)p->group=(pid_t)n;
            if(field==22)p->start=n;
        }
        if(end)s=end+1;
    }return 0;
}
static int proc_list(struct identity *p,size_t *count){
    DIR *d=opendir("/proc");if(!d)return -1;struct dirent *e;size_t n=0;int result=0;
    while((e=readdir(d))){char *end;long pid=strtol(e->d_name,&end,10);if(*end||pid<=1||pid>INT_MAX)continue;
        if(n==MAXPROC){errno=EOVERFLOW;result=-1;break;}
        if(process((pid_t)pid,&p[n])){if(errno==ENOENT||errno==ESRCH)continue;result=-1;break;}n++;
    }closedir(d);*count=n;return result;
}
static int adbd_absent(void){
    struct identity p[MAXPROC];size_t n;if(proc_list(p,&n))return 0;
    for(size_t i=0;i<n;i++){char path[64],comm[64];snprintf(path,sizeof path,"/proc/%ld/comm",(long)p[i].pid);
        if(value(path,comm,sizeof comm)<0){if(errno==ENOENT||errno==ESRCH)continue;return 0;}
        if(!strcmp(comm,"adbd")&&p[i].state!='Z')return 0;
    }return 1;
}
static void null_stdio(void){int fd=open("/dev/null",O_RDWR|O_CLOEXEC);if(fd<0)_exit(127);for(int i=0;i<3;i++)if(dup2(fd,i)<0)_exit(127);if(fd>2)close(fd);}
static int reserve_stdio(void){for(int i=0;i<3;i++)if(fcntl(i,F_GETFD)<0){if(errno!=EBADF)return -1;int fd=open("/dev/null",O_RDWR);if(fd<0)return -1;if(fd!=i){if(dup2(fd,i)<0){close(fd);return -1;}close(fd);}}return 0;}
static int wait_owned(pid_t pid,unsigned ms){
    int st;int64_t end=now_ms()+ms;
    do{pid_t r=waitpid(pid,&st,WNOHANG);if(r==pid)return WIFEXITED(st)?WEXITSTATUS(st):-1;if(r<0&&errno!=EINTR)return -1;tick();}while(now_ms()<end);
    kill(pid,SIGKILL);end=now_ms()+1000;
    do{pid_t r=waitpid(pid,&st,WNOHANG);if(r==pid||(r<0&&errno==ECHILD))return -1;tick();}while(now_ms()<end);
    return -2;
}
static int hash_matches(const char *path,const char *sha){
    int f[2];if(pipe2(f,O_CLOEXEC))return 0;pid_t child=fork();
    if(!child){close(f[0]);null_stdio();if(dup2(f[1],1)<0)_exit(127);close(f[1]);execl(BB,"busybox","sha256sum",path,(char*)NULL);_exit(127);}
    close(f[1]);if(child<0){close(f[0]);return 0;}
    struct pollfd p={f[0],POLLIN,0};char s[65]={0};ssize_t got=-1;
    if(poll(&p,1,3000)>0)got=read(f[0],s,64);
    close(f[0]);int rc=wait_owned(child,1000);
    return rc==0&&got==64&&!memcmp(s,sha,64);
}
static int enum_functions(int with_adb){
    DIR *d=opendir(G "/functions");if(!d)return 0;unsigned mask=0;int adb=0,ok=1;struct dirent *e;
    while((e=readdir(d))){if(e->d_name[0]=='.')continue;int found=0;for(unsigned i=0;i<5;i++)if(!strcmp(e->d_name,fn[i])){mask|=1U<<i;found=1;}
        if(!strcmp(e->d_name,"ffs.adb")){adb++;found=with_adb;}if(!found)ok=0;
    }closedir(d);return ok&&mask==31&&adb==with_adb;
}
static int topology(int with_function,int with_link,int capture){
    if(!enum_functions(with_function))return 0;
    DIR *gad=opendir("/sys/kernel/config/usb_gadget");if(!gad)return 0;struct dirent *e;int count=0,ok=1;
    while((e=readdir(gad)))if(e->d_name[0]!='.'){count++;if(strcmp(e->d_name,"g1"))ok=0;}
    closedir(gad);if(!ok||count!=1)return 0;
    DIR *configs=opendir(G "/configs");if(!configs)return 0;unsigned cmask=0;
    while((e=readdir(configs))){if(e->d_name[0]=='.')continue;if(strlen(e->d_name)!=3||e->d_name[0]!='b'||e->d_name[1]!='.'||e->d_name[2]<'1'||e->d_name[2]>'4'){ok=0;break;}cmask|=1U<<(e->d_name[2]-'1');}
    closedir(configs);if(!ok||cmask!=15)return 0;
    for(unsigned i=0;i<7;i++){char path[180];snprintf(path,sizeof path,G "/%s",desc[i]);if(!exact(path,expected_desc[i]))return 0;}
    for(unsigned c=0;c<4;c++){
        char path[256];snprintf(path,sizeof path,G "/configs/b.%u",c+1);DIR *d=opendir(path);if(!d)return 0;unsigned mask=0;int adb=0;
        while((e=readdir(d))){if(e->d_name[0]=='.')continue;snprintf(path,sizeof path,G "/configs/b.%u/%.128s",c+1,e->d_name);struct stat st;if(lstat(path,&st)){ok=0;break;}if(!S_ISLNK(st.st_mode))continue;
            char dest[256],resolved[PATH_MAX],expected[PATH_MAX];ssize_t n=readlink(path,dest,sizeof dest-1);if(n<0||(size_t)n>=sizeof dest-1){ok=0;break;}dest[n]=0;
            int found=0;for(unsigned i=0;i<5;i++)if(!strcmp(e->d_name,fn[i])){snprintf(expected,sizeof expected,G "/functions/%s",fn[i]);if(!realpath(path,resolved)||strcmp(resolved,expected)){ok=0;break;}mask|=1U<<i;found=1;}
            if(!strcmp(e->d_name,"ffs.adb")){adb++;found=(c==0&&with_link);if(!realpath(path,resolved)||strcmp(resolved,FF))ok=0;}
            if(!found)ok=0;
        }closedir(d);if(!ok||mask!=config_mask(c)||adb!=((c==0)?with_link:0))return 0;
        const char *names[]={"bmAttributes","MaxPower"};
        for(unsigned j=0;j<2;j++){char v[32];snprintf(path,sizeof path,G "/configs/b.%u/%s",c+1,names[j]);if(value(path,v,sizeof v)<0)return 0;if(capture)strcpy(attrs[c][j],v);else if(strcmp(v,attrs[c][j]))return 0;}
    }return 1;
}
static int mounts(int want){
    FILE *f=fopen("/proc/mounts","re");if(!f)return 0;char line[4096];int count=0,match=0,ok=1;
    while(fgets(line,sizeof line,f)){if(!strchr(line,'\n')){ok=0;break;}char source[256],path[256],type[64];if(sscanf(line,"%255s %255s %63s",source,path,type)!=3){ok=0;break;}
        if(!strcmp(type,"functionfs")){count++;if(!strcmp(path,MP)&&!strcmp(source,"adb"))match++;}
        if(!strcmp(path,MP)&&strcmp(type,"functionfs"))ok=0;
    }if(ferror(f))ok=0;fclose(f);return ok&&count==want&&match==want;
}
static int listeners_read(struct listeners *out){
    out->n=0;const char *paths[]={"/proc/net/tcp","/proc/net/tcp6"};
    for(unsigned family=0;family<2;family++){
        FILE *f=fopen(paths[family],"re");if(!f){if(family&&errno==ENOENT)continue;return -1;}char line[1024];int first=1;
        while(fgets(line,sizeof line,f)){if(!strchr(line,'\n')){fclose(f);return -1;}if(first){first=0;continue;}
            char local[65],remote[65],state[3];if(sscanf(line,"%*u: %64s %64s %2s",local,remote,state)!=3){fclose(f);return -1;}if(strcmp(state,"0A"))continue;
            char *colon=strrchr(local,':');if(!colon){fclose(f);return -1;}for(char *p=local;*p;p++)if(*p!=':'&&!isxdigit((unsigned char)*p)){fclose(f);return -1;}
            if(!strcmp(colon+1,"15B3")){if(status_fd>=0){dprintf(status_fd,"observed_tcp_listener_port 5555\n");fsync(status_fd);}fclose(f);return -1;}if(out->n==MAXLISTEN){fclose(f);return -1;}
            snprintf(out->entries[out->n++],80,"%u:%s",family,local);
        }int bad=ferror(f);fclose(f);if(bad)return -1;
    }return 0;
}
static int listeners_match(const struct listeners *current,int allow_stock_5037,unsigned *observed){
    *observed=0;
    for(unsigned i=0;i<current->n;i++){
        int found=0;for(unsigned j=0;j<initial_listeners.n;j++)if(!strcmp(current->entries[i],initial_listeners.entries[j]))found=1;
        if(found)continue;
        const char *colon=strrchr(current->entries[i],':');if(!colon)return 0;
        *observed=(unsigned)strtoul(colon+1,NULL,16);
        if(!allow_stock_5037||strcmp(current->entries[i],"0:00000000:13AD"))return 0;
    }return 1;
}
/* Managed operation validates only the owned daemon's TCP listeners.
 * Stock services and the separately verified loopback provider may restart.
 * owner==NULL is a preflight check for the daemon's one TCP port. */
static int managed_socket_policy(const struct identity *owner){
    unsigned long long sockets[256];unsigned count=0;
    if(owner){
        struct identity fresh;
        if(process(owner->pid,&fresh)||fresh.start!=owner->start||fresh.state=='Z')return 0;
        char root[64];snprintf(root,sizeof root,"/proc/%ld/fd",(long)owner->pid);
        DIR *fds=opendir(root);if(!fds)return 0;struct dirent *entry;int ok=1;
        while((entry=readdir(fds))){
            if(entry->d_name[0]=='.')continue;
            char path[384],link[128];int length=snprintf(path,sizeof path,"%s/%s",root,entry->d_name);
            if(length<0||(size_t)length>=sizeof path){ok=0;break;}
            ssize_t n=readlink(path,link,sizeof link-1);
            if(n<0){if(errno==ENOENT)continue;ok=0;break;}
            if((size_t)n>=sizeof link-1){ok=0;break;}link[n]=0;
            unsigned long long inode;int used=0;
            if(sscanf(link,"socket:[%llu]%n",&inode,&used)==1&&used==n&&inode){
                if(count==256){ok=0;break;}sockets[count++]=inode;
            }
        }
        closedir(fds);if(!ok)return 0;
    }
    const char *paths[]={"/proc/net/tcp","/proc/net/tcp6"};
    for(unsigned family=0;family<2;family++){
        FILE *file=fopen(paths[family],"re");if(!file){if(family&&errno==ENOENT)continue;return 0;}
        char line[1024];int first=1,ok=1;
        while(fgets(line,sizeof line,file)){
            if(!strchr(line,'\n')){ok=0;break;}if(first){first=0;continue;}
            char local[65],state[3];unsigned long long inode;
            if(sscanf(line,"%*u: %64s %*64s %2s %*s %*s %*s %*s %*s %llu",local,state,&inode)!=3){ok=0;break;}
            if(strcmp(state,"0A"))continue;
            if(!owner){const char *colon=strrchr(local,':');if(!colon||!strcmp(colon+1,"13AD")){ok=0;break;}}
            else{
                int mine=0;for(unsigned i=0;i<count;i++)if(sockets[i]==inode){mine=1;break;}
                if(mine&&(family||strcmp(local,"00000000:13AD"))){ok=0;break;}
            }
        }
        if(ferror(file))ok=0;
        fclose(file);if(!ok)return 0;
    }
    if(owner){struct identity fresh;if(process(owner->pid,&fresh)||fresh.start!=owner->start||fresh.state=='Z')return 0;}
    return 1;
}
/* restore() has already proved owned descendants stopped and adbd absent. */
static int listeners_unchanged(void){if(managed_usb)return 1;struct listeners current;unsigned observed;if(listeners_read(&current))return 0;return listeners_match(&current,0,&observed);}
static int listeners_during_trial(void){
    if(managed_usb)return managed_socket_policy(&managed_adb);
    static int reported_5037;struct listeners current;unsigned observed;
    if(listeners_read(&current))return 0;
    int ok=listeners_match(&current,1,&observed);
    if(observed&&(!ok||!reported_5037)){
        if(status_fd>=0){dprintf(status_fd,"observed_tcp_listener_port %u\n",observed);fsync(status_fd);}
        if(ok&&observed==5037)reported_5037=1;
    }return ok;
}
static int no_initial_adb_server(void){
    for(unsigned i=0;i<initial_listeners.n;i++){
        const char *colon=strrchr(initial_listeners.entries[i],':');if(!colon||!strcmp(colon+1,"13AD"))return 0;
    }return 1;
}
static int endpoint(const char *path){struct stat s;return !lstat(path,&s)&&S_ISREG(s.st_mode)&&s.st_uid==2000;}
static int audit_library_ready(void){
    struct stat st;snprintf(audit_library,sizeof audit_library,"%s/libax520-ep0-audit.so",directory);
    return !lstat(audit_library,&st)&&S_ISREG(st.st_mode)&&st.st_uid==0&&(st.st_mode&0777)==0600&&hash_matches(audit_library,audit_sha);
}
static int prepare_audit_log(void){
    char path[180];snprintf(path,sizeof path,"%s/ep0-audit.log",directory);
    return open(path,O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_NOFOLLOW,0600);
}
static int capture_ptp_link(void){
    ssize_t n=readlink(PTPL,original_ptp_link,sizeof original_ptp_link-1);
    if(n<=0||(size_t)n>=sizeof original_ptp_link-1)return 0;
    original_ptp_link[n]=0;return 1;
}
static int preflight(void){
    return getuid()==0&&geteuid()==0&&exact(G "/UDC",UDC)&&topology(0,0,1)&&capture_ptp_link()&&adbd_absent()&&
        absent(FF)&&absent(FL)&&absent("/dev/usb-ffs")&&absent("/dev/android_adb")&&mounts(0)&&
        hash_matches(ADB,adb_sha)&&hash_matches("/lib/ld-uClibc.so.0",loader_sha)&&hash_matches("/lib/libc.so.0",libc_sha)&&
        (managed_usb?managed_socket_policy(NULL):(!listeners_read(&initial_listeners)&&no_initial_adb_server()))&&audit_library_ready()&&(!getenv("LD_PRELOAD")||!getenv("LD_PRELOAD")[0]);
}
static int udc_empty(void){return exact(G "/UDC","");}
static int unbind(void){owned->unbind_attempted=1;if(udc_empty())return 0;if(write_value(G "/UDC","\n")){int e=errno;return e==ENODEV&&udc_empty()?0:-1;}return udc_empty()?0:-1;}
static sigset_t mutation_old_mask;
static int mutation_begin(int kind){sigset_t set;sigemptyset(&set);sigaddset(&set,SIGTERM);sigaddset(&set,SIGINT);if(sigprocmask(SIG_BLOCK,&set,&mutation_old_mask))return -1;owned->mutation=kind;if(status_fd>=0){dprintf(status_fd,"mutation_intent %d\n",kind);fsync(status_fd);}return 0;}
static void mutation_end(void){int e=errno;owned->mutation=0;sigprocmask(SIG_SETMASK,&mutation_old_mask,NULL);errno=e;}
static int remove_config1_ptp(void){
    char current[256];ssize_t n=readlink(PTPL,current,sizeof current-1);
    if(n<=0||(size_t)n>=sizeof current-1){errno=EINVAL;return -1;}current[n]=0;
    if(strcmp(current,original_ptp_link)){errno=ESTALE;return -1;}
    if(mutation_begin(6))return -1;
    int rc=unlink(PTPL);if(!rc)owned->ptp_removed=1;mutation_end();return rc;
}
static int restore_config1_ptp(void){
    if(!owned->ptp_removed||!original_ptp_link[0]||!absent(PTPL)){errno=EEXIST;return -1;}
    /* Configfs resolves symlink() targets from process cwd, then synthesizes
       readlink() relative to its item topology. Replaying that string is wrong. */
    if(symlink(G "/functions/iphone_ptp.gs0",PTPL))return -1;
    char generated[256];ssize_t n=readlink(PTPL,generated,sizeof generated-1);
    if(n<=0||(size_t)n>=sizeof generated-1){errno=EINVAL;return -1;}generated[n]=0;
    if(strcmp(generated,original_ptp_link)){errno=ESTALE;return -1;}
    owned->ptp_removed=0;return 0;
}
static int create_owned(const char *path,mode_t mode,volatile sig_atomic_t *flag,int kind){
    if(mutation_begin(kind))return -1;
    int rc=mkdir(path,mode);
    if(!rc){*flag=1;if(mode==0755)rc=chmod(path,0755);}mutation_end();return rc;
}
static void setup_worker(pid_t supervisor_pid){
    signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=supervisor_pid||setpgid(0,0))_exit(20);
    if(!exact(G "/UDC",UDC)||!topology(0,0,0)||!adbd_absent()||!mounts(0))_exit(21);
    if(create_owned(FF,0700,&owned->function,1)){errnote("function_create_failed");_exit(22);}note("function_created");
    if(create_owned("/dev/usb-ffs",0755,&owned->rootdir,2)){errnote("mount_parent_create_or_chmod_failed");_exit(22);}
    if(create_owned(MP,0700,&owned->mountdir,3)){errnote("mount_directory_create_failed");_exit(22);}
    if(mutation_begin(4))_exit(22);
    int mount_rc=mount("adb",MP,"functionfs",0,"uid=2000,gid=2000");if(!mount_rc)owned->mounted=1;mutation_end();
    if(mount_rc){errnote("functionfs_mount_failed");_exit(22);}note("functionfs_mounted");
    if(!mounts(1)||!endpoint(MP "/ep0")||!absent("/dev/android_adb")||!topology(1,0,0))_exit(23);
    note("ep0_verified");
    if(unbind()){errnote("udc_unbind_failed");_exit(24);}note("stock_udc_unbound");
    if(remove_config1_ptp()){errnote("config1_ptp_remove_failed");_exit(25);}note("config1_ptp_removed");
    if(mutation_begin(5))_exit(25);
    int link_rc=symlink(FF,FL);if(!link_rc)owned->link=1;mutation_end();
    if(link_rc){errnote("adb_link_create_failed");_exit(25);}note("adb_link_created");
    if(!udc_empty()||!topology(1,1,0)||!mounts(1)||!endpoint(MP "/ep0")||!absent("/dev/android_adb"))_exit(25);
    int audit_fd=prepare_audit_log();if(audit_fd<0){errnote("ep0_audit_log_failed");_exit(26);}note("ep0_audit_prepared");
    pid_t worker_pid=getpid(),child=fork();if(child<0){close(audit_fd);_exit(26);}
    if(!child){if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=worker_pid||setpgid(0,0))_exit(127);if(!mounts(1)||!endpoint(MP "/ep0")||!absent("/dev/android_adb"))_exit(127);char audit_fd_text[32];snprintf(audit_fd_text,sizeof audit_fd_text,"%d",audit_fd);if(setenv("ADB_TRANSPORT_PORT","0",1)||setenv("AX520_EP0_AUDIT_FD",audit_fd_text,1)||setenv("LD_PRELOAD",audit_library,1))_exit(127);note("transport_zero_selected");null_stdio();if(status_fd>=0)close(status_fd);execl(ADB,"adbd",(char*)NULL);_exit(127);}
    close(audit_fd);
    struct identity adb={0};int64_t end=now_ms()+1000;
    while(process(child,&adb)&&now_ms()<end)tick();
    if(adb.pid!=child||!adb.start)_exit(26);
    if(managed_usb)managed_adb=adb;
    if(status_fd>=0){dprintf(status_fd,"owned_adbd_pid %ld\nowned_adbd_start %llu\n",(long)child,adb.start);fsync(status_fd);}
    end=now_ms()+15000;
    while(now_ms()<end){
        struct identity current;if(process(child,&current)||current.start!=adb.start||current.state=='Z'){note("adbd_exited_before_ready");_exit(27);}
        if(!listeners_during_trial()){note("unexpected_tcp_listener");_exit(28);}
        if(exact(G "/UDC",UDC)&&endpoint(MP "/ep1")&&endpoint(MP "/ep2")&&topology(1,1,0)){owned->ready=1;note("adb_usb_ready");break;}tick();
    }
    if(!owned->ready){dprintf(status_fd,"adb_readiness_mask %d\n",(exact(G "/UDC",UDC)?1:0)|(endpoint(MP "/ep1")?2:0)|(endpoint(MP "/ep2")?4:0)|(topology(1,1,0)?8:0));note("adb_ready_deadline");_exit(29);}
    for(;;){struct identity current;if(process(child,&current)||current.start!=adb.start||current.state=='Z')_exit(27);
        if(!listeners_during_trial()){note("unexpected_tcp_listener");_exit(28);}if(!topology(1,1,0)||!exact(G "/UDC",UDC)||!mounts(1)){note("trial_state_changed");_exit(29);}struct timespec pause={0,250000000};nanosleep(&pause,NULL);}
}
static int descendants(struct identity *list,size_t *count){
    size_t n;if(proc_list(list,&n))return -1;unsigned char mark[MAXPROC]={0};int changed;
    do{changed=0;for(size_t i=0;i<n;i++){if(mark[i])continue;int belongs=list[i].parent==getpid();for(size_t j=0;!belongs&&j<n;j++)if(mark[j]&&list[i].parent==list[j].pid)belongs=1;if(belongs){mark[i]=1;changed=1;}}}while(changed);
    size_t out=0;for(size_t i=0;i<n;i++)if(mark[i])list[out++]=list[i];*count=out;return 0;
}
static int stop_descendants(void){
    int64_t start=now_ms(),end=start+6000;
    do{struct identity p[MAXPROC];size_t n;if(descendants(p,&n))return -1;int live=0;
        for(size_t i=0;i<n;i++){if(p[i].state=='Z')continue;live++;struct identity fresh;if(process(p[i].pid,&fresh)){if(errno==ENOENT||errno==ESRCH)continue;return -1;}if(fresh.start!=p[i].start)return -1;
            if(kill(fresh.pid,now_ms()-start<1000?SIGTERM:SIGKILL)&&errno!=ESRCH)return -1;}
        for(;;){int st;pid_t r=waitpid(-1,&st,WNOHANG);if(r>0)continue;if(r<0&&errno==EINTR)continue;break;}
        if(!live){int st;pid_t r=waitpid(-1,&st,WNOHANG);if(r<0&&errno==ECHILD)return 0;}
        tick();
    }while(now_ms()<end);return -1;
}
enum cleanup_op {OP_UNBIND,OP_UNLINK,OP_UMOUNT,OP_RMDIR_MOUNT,OP_RMDIR_PARENT,OP_RMDIR_FUNC,OP_RESTORE_PTP,OP_BIND};
static int operation(enum cleanup_op op){
    switch(op){
    case OP_UNBIND:return unbind();
    case OP_UNLINK:if(unlink(FL))return -1;owned->link=0;return 0;
    case OP_UMOUNT:if(umount(MP))return -1;owned->mounted=0;return 0;
    case OP_RMDIR_MOUNT:if(rmdir(MP))return -1;owned->mountdir=0;return 0;
    case OP_RMDIR_PARENT:if(rmdir("/dev/usb-ffs"))return -1;owned->rootdir=0;return 0;
    case OP_RMDIR_FUNC:if(rmdir(FF))return -1;owned->function=0;return 0;
    case OP_RESTORE_PTP:return restore_config1_ptp();
    case OP_BIND:if(write_value(G "/UDC",UDC "\n"))return -1;return exact(G "/UDC",UDC)?0:-1;
    }return -1;
}
static int bounded_operation(enum cleanup_op op){
    pid_t p=fork();if(p<0)return -1;if(!p){int rc=operation(op);if(rc)errnote("restore_operation_errno");_exit(rc?1:0);}int rc=wait_owned(p,2500);if(rc==-2)note("restore_child_stop_unverified");return rc;
}
static int restore(void){
    if(owned->mutation){note("mutation_ownership_unverified");return -1;}
    if(!topology(owned->function,owned->link,0)){note("restore_topology_changed");return -1;}
    if(owned->unbind_attempted||owned->link){char current[64];if(value(G "/UDC",current,sizeof current)<0||(current[0]&&strcmp(current,UDC))){note("restore_udc_other");return -1;}
        if(bounded_operation(OP_UNBIND)){note("restore_unbind_failed");return -1;}}
    if(owned->link&&bounded_operation(OP_UNLINK)){note("restore_unlink_failed");return -1;}
    if(owned->mounted&&(!mounts(1)||bounded_operation(OP_UMOUNT))){note("restore_unmount_failed");return -1;}
    if(owned->mountdir&&bounded_operation(OP_RMDIR_MOUNT)){note("restore_mountdir_failed");return -1;}
    if(owned->rootdir&&bounded_operation(OP_RMDIR_PARENT)){note("restore_parentdir_failed");return -1;}
    if(owned->function&&bounded_operation(OP_RMDIR_FUNC)){note("restore_function_failed");return -1;}
    if(owned->ptp_removed){if(bounded_operation(OP_RESTORE_PTP)){note("restore_ptp_link_failed");return -1;}note("config1_ptp_restored");}
    if(!topology(0,0,0)||!mounts(0)||!absent("/dev/usb-ffs")||!adbd_absent()){note("restore_baseline_unverified");return -1;}
    int network_ok=listeners_unchanged();if(!network_ok)note("network_state_unverified");
    if(owned->unbind_attempted&&bounded_operation(OP_BIND)){note("restore_rebind_failed");return -1;}
    return exact(G "/UDC",UDC)&&topology(0,0,0)&&network_ok?0:-1;
}
static void supervisor(int handshake){
    if(setsid()<0||prctl(PR_SET_CHILD_SUBREAPER,1))_exit(30);
    null_stdio();signal(SIGHUP,SIG_IGN);signal(SIGPIPE,SIG_IGN);signal(SIGCHLD,SIG_DFL);signal(SIGTERM,signal_stop);signal(SIGINT,signal_stop);
    struct identity self;if(process(getpid(),&self)||!self.start)_exit(30);int64_t end=managed_usb?INT64_MAX:now_ms()+90000;
    char path[180];snprintf(path,sizeof path,"%s/guard",directory);int fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)_exit(30);
    dprintf(fd,"%ld %llu %lld\n",(long)getpid(),self.start,(long long)end);fsync(fd);close(fd);if(managed_usb)note("mode managed_usb");note("watchdog_armed");
    if(write(handshake,"A",1)!=1)_exit(30);
    close(handshake);
    pid_t supervisor_pid=getpid(),child=fork();if(!child){setup_worker(supervisor_pid);_exit(20);}if(child<0){note("worker_fork_failed");_exit(30);}
    while(!interrupted&&now_ms()<end){siginfo_t info={0};if(waitid(P_PID,(id_t)child,&info,WEXITED|WNOHANG|WNOWAIT)==0&&info.si_pid){dprintf(status_fd,"worker_exit_status %d\n",info.si_status);fsync(status_fd);break;}tick();}
    note("restoration_started");if(stop_descendants()){note("owned_descendants_stop_unverified");note("result_unverified_no_retry");_exit(31);}note("owned_descendants_stopped");
    if(restore()){note("result_unverified_no_retry");_exit(32);}note("result_restored_device_state");unlink(path);_exit(0);
}
int main(int argc,char **argv){
    if(argc!=3||(strcmp(argv[1],"--run")&&strcmp(argv[1],"--managed"))||getuid()||geteuid()||reserve_stdio())return 2;
    managed_usb=!strcmp(argv[1],"--managed");
    const char *prefix="/tmp/ax520-adb-";size_t n=strlen(prefix);if(strncmp(argv[2],prefix,n)||strlen(argv[2])!=n+12)return 2;
    for(size_t i=n;argv[2][i];i++)if(!isdigit((unsigned char)argv[2][i])&&(argv[2][i]<'a'||argv[2][i]>'f'))return 2;
    struct stat st;if(lstat(argv[2],&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0700)return 2;strcpy(directory,argv[2]);umask(077);
    int lock=open("/tmp/ax520-adb-trial.lock",O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK,0600);
    if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||(st.st_mode&0777)!=0600||st.st_nlink!=1||flock(lock,LOCK_EX|LOCK_NB))return 2;
    if(!preflight()){puts("ADB_PREFLIGHT_BLOCKED");return 3;}
    char path[180];snprintf(path,sizeof path,"%s/status",directory);status_fd=open(path,O_CREAT|O_EXCL|O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0600);if(status_fd<0)return 3;
    owned=mmap(NULL,sizeof *owned,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);if(owned==MAP_FAILED)return 3;memset(owned,0,sizeof *owned);
    note("preflight_verified");int f[2];if(pipe2(f,O_CLOEXEC))return 3;pid_t p=fork();if(!p){close(f[0]);supervisor(f[1]);_exit(30);}close(f[1]);if(p<0){close(f[0]);return 3;}
    struct pollfd wait={f[0],POLLIN,0};char mark=0;if(poll(&wait,1,5000)>0)read(f[0],&mark,1);close(f[0]);
    if(mark!='A'){puts("ADB_LAUNCH_UNVERIFIED_NO_RETRY");return 4;}
    printf("ADB_WATCHDOG_PID=%ld\nADB_STATUS=%s/status\n",(long)p,directory);return 0;
}

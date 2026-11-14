#define main controller_main_unused
#include "usb.c"
#undef main
#include <assert.h>

static void linger(void){signal(SIGTERM,SIG_IGN);for(;;)pause();}
int main(void){
    assert(!prctl(PR_SET_CHILD_SUBREAPER,1));
    struct identity self;assert(!process(getpid(),&self)&&self.start>0);
    int channel[2];assert(!pipe(channel));pid_t worker=fork();assert(worker>=0);
    if(!worker){
        close(channel[0]);pid_t daemon=fork();assert(daemon>=0);
        if(!daemon){assert(setsid()>0);pid_t shell=fork();assert(shell>=0);if(!shell){assert(setsid()>0);linger();}_exit(0);}
        assert(write(channel[1],&daemon,sizeof daemon)==sizeof daemon);close(channel[1]);_exit(0);
    }
    close(channel[1]);pid_t daemon;assert(read(channel[0],&daemon,sizeof daemon)==sizeof daemon);close(channel[0]);
    int st;assert(waitpid(worker,&st,0)==worker);
    /* Let double-forked, session-detached shell become adopted by this subreaper. */
    int64_t settle=now_ms()+200;while(now_ms()<settle)tick();
    struct identity children[MAXPROC];size_t count;assert(!descendants(children,&count)&&count>=1);
    int64_t begin=now_ms();assert(!stop_descendants()&&now_ms()-begin<6500);
    assert(!descendants(children,&count)&&count==0);
    assert(waitpid(-1,&st,WNOHANG)<0&&errno==ECHILD);
    puts("PASS subreaper cleanup catches double-forked setsid descendants and reaps all children");

    owned=mmap(NULL,sizeof *owned,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);assert(owned!=MAP_FAILED);
    memset(owned,0,sizeof *owned);assert(!pipe(channel));worker=fork();assert(worker>=0);
    if(!worker){
        signal(SIGTERM,SIG_DFL);close(channel[0]);assert(!mutation_begin(5));
        assert(write(channel[1],"I",1)==1);close(channel[1]);
        int64_t end=now_ms()+200;while(now_ms()<end)tick();
        owned->link=1;mutation_end();_exit(0);
    }
    close(channel[1]);char mark;assert(read(channel[0],&mark,1)==1&&mark=='I');close(channel[0]);
    assert(!kill(worker,SIGTERM));assert(waitpid(worker,&st,0)==worker);
    assert(WIFSIGNALED(st)&&WTERMSIG(st)==SIGTERM&&owned->link==1&&owned->mutation==0);
    puts("PASS queued TERM cannot interrupt mutation success before ownership commit");

    char temp[]="/tmp/adb-mode-test-XXXXXX";assert(mkdtemp(temp));char path[128];snprintf(path,sizeof path,"%s/parent",temp);
    owned->rootdir=0;umask(077);assert(!create_owned(path,0755,&owned->rootdir,2));
    struct stat mode;assert(!stat(path,&mode)&&(mode.st_mode&0777)==0755&&owned->rootdir==1);
    assert(!rmdir(path)&&!rmdir(temp));
    puts("PASS owned FunctionFS parent remains traversable0755 despite private umask");
    puts("No USB, network, mount, stock executable or target operations executed.");
    return 0;
}

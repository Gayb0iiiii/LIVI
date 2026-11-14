#define main trial_original_main
#define readlink fixture_readlink
#define symlink fixture_symlink
#define lstat fixture_lstat
#include "usb.c"
#undef main
#undef readlink
#undef symlink
#undef lstat
#include <assert.h>
static int exists, created, force_mismatch;
int fixture_lstat(const char *p,struct stat *st){assert(!strcmp(p,PTPL));if(!exists){errno=ENOENT;return -1;}memset(st,0,sizeof *st);st->st_mode=S_IFLNK|0777;return 0;}
int fixture_symlink(const char *target,const char *link){assert(!strcmp(link,PTPL));if(strcmp(target,G "/functions/iphone_ptp.gs0")){errno=ENOENT;return -1;}assert(!exists);exists=1;created++;return 0;}
ssize_t fixture_readlink(const char *p,char *out,size_t cap){assert(!strcmp(p,PTPL));assert(exists);const char *canonical=force_mismatch?"../unexpected":"../../../../usb_gadget/g1/functions/iphone_ptp.gs0";size_t n=strlen(canonical);assert(cap>=n);memcpy(out,canonical,n);return (ssize_t)n;}
int main(void){struct shared state={0};owned=&state;status_fd=-1;strcpy(original_ptp_link,"../../../../usb_gadget/g1/functions/iphone_ptp.gs0");owned->ptp_removed=1;
 assert(!restore_config1_ptp());assert(created==1&&exists&&!owned->ptp_removed);
 exists=0;force_mismatch=1;owned->ptp_removed=1;assert(restore_config1_ptp()==-1);assert(created==2&&exists&&owned->ptp_removed&&errno==ESTALE);
 puts("PASS configfs restoration uses absolute target; canonical readlink must match before clearing ownership");return 0;}

/* SHA-256 over a bounded regular executable, FIPS 180-4 algorithm. */
#define _GNU_SOURCE
#include "radio.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static uint32_t rr(uint32_t v, unsigned n) { return (v >> n) | (v << (32 - n)); }
static void block(uint32_t s[8], const unsigned char b[64]) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (unsigned i=0;i<16;i++) w[i]=(uint32_t)b[i*4]<<24|(uint32_t)b[i*4+1]<<16|(uint32_t)b[i*4+2]<<8|b[i*4+3];
    for (unsigned i=16;i<64;i++) w[i]=w[i-16]+(rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10));
    uint32_t a=s[0],b0=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for (unsigned i=0;i<64;i++) {
        uint32_t t1=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b0)^(a&c)^(b0&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b0;b0=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b0;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
int sha256_file(const char *path, char hex[65]) {
    int f=open(path,O_RDONLY|O_CLOEXEC);struct stat st;
    if(f<0)return -1;
    if(fstat(f,&st)||!S_ISREG(st.st_mode)||st.st_size<0||st.st_size>16*1024*1024){close(f);errno=EINVAL;return -1;}
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned char b[64];size_t used=0;uint64_t total=0;
    for(;;){ssize_t n=read(f,b+used,sizeof b-used);if(n<0){if(errno==EINTR)continue;close(f);return -1;}if(!n)break;
        total+=(unsigned)n;used+=(unsigned)n;if(total>16*1024*1024){close(f);errno=EFBIG;return -1;}if(used==64){block(s,b);used=0;}}
    close(f);if(total!=(uint64_t)st.st_size){errno=ESTALE;return -1;}
    b[used++]=0x80;if(used>56){memset(b+used,0,64-used);block(s,b);used=0;}memset(b+used,0,56-used);
    uint64_t bits=total*8;for(unsigned i=0;i<8;i++)b[63-i]=(unsigned char)(bits>>(i*8));block(s,b);
    static const char alphabet[]="0123456789abcdef";
    for(unsigned i=0;i<32;i++){unsigned byte=(s[i/4]>>(24-(i%4)*8))&255;hex[i*2]=alphabet[byte>>4];hex[i*2+1]=alphabet[byte&15];}hex[64]=0;return 0;
}

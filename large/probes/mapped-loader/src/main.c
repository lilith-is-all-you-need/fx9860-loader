#include "loader.h"
#include <fxlarge/catalog.h>
void *memcpy(void *out,const void *in,size_t n){unsigned char *a=out;const unsigned char *b=in;while(n--)*a++=*b++;return out;}
static void screen(const char *a,const char *b)
{r_clear();r_print(0,0,(const unsigned char *)"KhiCAS Loader 0.1",0);r_print(0,18,(const unsigned char *)a,0);r_print(0,32,(const unsigned char *)b,0);r_display();}
static void wide(uint16_t *out,const char *s){while(*s)*out++=(unsigned char)*s++;*out=0;}
static void finalize(Context *c){r_quit(0);r_free(c);}
static int equal(const void *a,const void *b,unsigned n)
{const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void failure_report(const char *id,const char *why)
{
 uint16_t path[64];fx_path(path,id,"KLOAD.TXT");char b[512];
 int fd=r_open(path,1,0);if(fd<0)return;
 int n=r_read(fd,b,8,0),size=r_size(fd);r_close(fd);
 if(n!=8||size!=LOG_BYTES||!equal(b,"FXKLOAD1",8))return;
 for(unsigned i=0;i<sizeof b;i++)b[i]=' ';
 const char *h="FXKLOAD1\nSTART_FAILED=";unsigned j=0;while(*h)b[j++]=*h++;
 while(*why&&j<500){b[j++]=*why++;}
 b[j++]='\n';
 fd=r_open(path,2,0);if(fd<0)return;r_write(fd,b,sizeof b);r_close(fd);
}
static __attribute__((noinline)) int verify_image(Context *c,int fd)
{
 Sha256 hash;sha_init(&hash);unsigned char buffer[4096],digest[32];int ok=1;
 for(unsigned off=0;off<IMAGE_BYTES;off+=4096){
  unsigned n=IMAGE_BYTES-off;if(n>4096)n=4096;
  if(r_read(fd,buffer,n,off)!=(int)n){ok=0;break;}
  sha_update(&hash,buffer,n);uint32_t h=2166136261u;
  for(unsigned j=0;j<n;j++){h=(h^buffer[j])*16777619u;}
  c->hashes[off/4096]=h;
  if(!(off&0x7ffff))screen("Checking BIN hash","Please wait");
 }
 int closed=r_close(fd);sha_final(&hash,digest);
 return ok&&closed>=0&&equal(digest,c->profile.sha256,32);
}
int main(void)
{
 FxAppItem item={{0},{0}};int selected=fx_choose(&item,"KHICAS.KPF","FX / KHICAS APPS",3);if(!selected)return 1;
 if(selected<0){uint16_t oldpath[64];Profile oldprofile;fx_path(oldpath,"","KHICAS.KPF");
  if(!fx_exact(oldpath,&oldprofile,sizeof oldprofile)){screen("No KhiCAS apps","Copy FXAPPS folders");
   int key=0;while(key!=30002)r_getkey(&key);return 1;}}
 r_clear();r_print(0,0,(const unsigned char *)"KhiCAS Loader 0.2",0);
 r_print(0,14,(const unsigned char *)"MENU return untested",0);
 r_print(0,26,(const unsigned char *)"Try EXE to resume",0);
 r_print(0,38,(const unsigned char *)"Reload: RUN-MAT first",0);
 r_print(0,52,(const unsigned char *)"EXE start; EXIT quit",0);r_display();
 {int key=0;while(key!=30004&&key!=30002)r_getkey(&key);if(key==30002)return 1;}
 Context *c=0;const char *why="Allocation failed";
 screen("Checking files","Please wait");
 uint32_t sp;__asm__ volatile("mov r15,%0":"=r"(sp));
 if(sp<0x8804c000u||sp>=0x88051000u){why="Unsupported stack";goto fail;}
 unsigned bytes=resident_end-resident_begin;
 unsigned total=(sizeof(Context)+31u+bytes+8191u+16384u+31u)&~31u;
 if(total>45056){why="Resident too large";goto fail;}
 c=r_malloc(total);if(!c)goto fail;
 uintptr_t start=(uintptr_t)c,end=start+total;
 if(start<0x88040000u||end>WORK_BASE-4096||end<start){why="Heap conflicts";goto fail;}
 for(unsigned i=0;i<sizeof *c;i++)((unsigned char *)c)[i]=0;
 c->finalize=finalize;c->allocation_bytes=total;c->runner_bytes=bytes;c->ram_word=REG(0x08100000);
 fx_path(c->log_path,item.id,"KLOAD.TXT");fx_path(c->bin_path,item.id,item.id[0]?"IMAGE.BIN":"khicas.bin");wide(c->self_path,"\\\\fls0\\KLoad.g1a");
 uint16_t path[64];fx_path(path,item.id,"KHICAS.KPF");
 int fd=r_open(path,1,0);
 if(fd<0){why="Missing khicas.kpf";goto fail;}
 int got=r_size(fd)==sizeof(Profile)?r_read(fd,&c->profile,sizeof(Profile),0):-1;
 int closed=r_close(fd);
 if(got!=sizeof(Profile)||closed<0||!equal(c->profile.magic,"FXKHP001",8)||c->profile.version!=1||
    c->profile.bytes!=IMAGE_BYTES||c->profile.count!=54||c->profile.work_base!=WORK_BASE){why="Invalid profile";goto fail;}
 static const unsigned char approved[32]={0x4a,0x9d,0x1c,0x18,0x00,0x9d,0x98,0x7d,0xc7,0xc8,0x74,0x5b,0x7f,0xc0,0x99,0xb3,0xc6,0xe8,0x00,0x6e,0xbb,0xb2,0xee,0x5e,0x4b,0x48,0x39,0x34,0xbe,0x75,0x74,0x73};
 if(!equal(c->profile.sha256,approved,32)){why="Unreviewed image";goto fail;}
 fd=r_open(c->bin_path,1,0);if(fd<0){why="Missing khicas.bin";goto fail;}
 if(r_size(fd)!=IMAGE_BYTES){r_close(fd);why="Wrong BIN size";goto fail;}
 if(!verify_image(c,fd)){why="BIN hash mismatch";goto fail;}
 uintptr_t runner=(start+sizeof(Context)+31)&~31u;c->resident=runner|0x20000000u;
 c->shadow=(runner+bytes+8191)&~8191u;
 if(c->shadow+16384>end){why="Allocation bounds";goto fail;}
 for(unsigned i=0;i<bytes;i+=32){purge(runner+i);}
 BARRIER();
 for(unsigned i=0;i<bytes;i++)BYTE(c->resident+i)=resident_begin[i];
 if(resident_fixups[0]>1023){why="Fixup count";goto fail;}
 for(unsigned i=1;i<=resident_fixups[0];i++){
  uint32_t off=resident_fixups[i];if(off+4>bytes||(off&3)){why="Fixup offset";goto fail;}
  uint32_t v=REG(c->resident+off);if(v<(uintptr_t)resident_begin||v>=(uintptr_t)resident_end){why="Fixup value";goto fail;}
  REG(c->resident+off)=v-(uintptr_t)resident_begin+c->resident;
 }BARRIER();
 int (*run)(Context *)=(int(*)(Context *))(c->resident+(uintptr_t)resident_main-(uintptr_t)resident_begin);
 /* The target may draw directly to the LCD. An OS menu resume can reveal
    this OS buffer while GetKey still waits, so never leave a loading page. */
 screen("If back from MENU:","EXE: try resume");
 r_print(0,46,(const unsigned char *)"Or MENU > RUN-MAT",0);r_display();
 int result=run(c);r_quit(0);r_free(c);c=0;
 screen(result?"Stopped: see log":"KhiCAS returned","EXIT: back to menu");
 {int key=0;while(key!=30002&&key!=30010)r_getkey(&key);}return 1;
fail:
 if(c){r_free(c);}
 failure_report(item.id,why);screen("Loader not started",why);
 {int key=0;while(key!=30002&&key!=30010)r_getkey(&key);}return 1;
}

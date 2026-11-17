#include "loader.h"
#include "sha256.h"
#include "os-map-profile.h"
#include <fxlarge/catalog.h>
void *memcpy(void *out,const void *in,size_t n){unsigned char *a=out;const unsigned char *b=in;while(n--)*a++=*b++;return out;}
static uint8_t rd(void *p,uint32_t a){(void)p;return BYTE(a);}
static void wide(uint16_t *out,const char *p){while(*p)*out++=(unsigned char)*p++;*out=0;}
static void line(int y,const char *s){r_print(0,y,(const unsigned char *)s,0);}
static void hexline(int y,const char *label,uint32_t v)
{
 char buf[22];unsigned n=0;while(label[n]&&n<12){buf[n]=label[n];n++;}
 for(int i=7;i>=0;i--){unsigned x=(v>>(i*4))&15;buf[n++]=(char)(x<10?'0'+x:'A'+x-10);}buf[n]=0;line(y,buf);
}
static int storage_free(unsigned required)
{
 if(!required)return 0;
 uint16_t media[16];wide(media,"\\\\fls0");
 /* SH4 implementations may write a big-endian uint64, SH3/HLE uint32.
    Two sentinel observations distinguish them without an undersized buffer. */
 uint32_t a[2]={0,0},b[2]={0,1};
 if(r_media_free(media,a)<0||r_media_free(media,b)<0)return FXLARGE_STORAGE_FREE_ERROR;
 uint32_t free_bytes=a[1]==b[1]?(b[0]?0xffffffffu:b[1]):b[0];
 return free_bytes>=required?0:FXLARGE_STORAGE_FREE_ERROR;
}
static int runtime_header(const unsigned char *h,unsigned bytes)
{
 unsigned i=0;int modern=1,legacy=1;
 for(;i<16;i++){if(h[i]!=(unsigned char)"FXLARGE-PAYLOAD1"[i])modern=0;
  if(h[i]!=(unsigned char)"KHICAS-MAPPED/1\0"[i])legacy=0;}
 const uint32_t *p=(const uint32_t *)(const void *)(h+16);
 if((!modern&&!legacy)||p[0]!=1||p[1]!=BASE+512u||p[2]!=bytes-512u)return 0;
 unsigned reserved=28;
 if(modern){if(p[3]!=1||p[4]!=1)return 0;reserved=36;}
 for(i=reserved;i<512;i++)if(h[i])return 0;
 return 1;
}
static int scan(Context *c,const uint16_t *path)
{
 FxOsMapProfile os;int rc=fx_os_profile(rd,0,&os);if(rc)return 100+rc;
 int fd=r_open(path,1,0);if(fd<0)return 10;
 if(r_size(fd)!=(int)c->profile.image_bytes){r_close(fd);return 11;}
 uint32_t header[128];
 if(r_read(fd,header,512,0)!=512||!runtime_header((const unsigned char *)header,c->profile.image_bytes)){r_close(fd);return FXLARGE_RUNTIME_HEADER_ERROR;}
 Sha256 sha;unsigned char digest[32];sha256_init(&sha);
 for(unsigned p=0;p<c->profile.page_count;p++){
  uint32_t pa=0;int span=((int(*)(int,int,uint32_t *))(uintptr_t)os.query)(fd,(int)(p*4096),&pa);
  pa&=0x1fffffffu;
  if(span!=4096||(pa&4095)||pa<0x10000||pa>0x1fff000u){r_close(fd);return 12;}
  c->pages[p]=pa;unsigned bytes=c->profile.image_bytes-p*4096;if(bytes>4096)bytes=4096;
  sha256_update(&sha,(const volatile unsigned char *)(uintptr_t)(pa|0xa0000000u),bytes);
  /* Payload P0 pages use C=0; no virtual/physical cache synonym assumption. */
 }
 sha256_final(&sha,digest);
 if(r_close(fd)<0)return 13;
 for(unsigned i=0;i<32;i++)if(digest[i]!=c->profile.sha256[i])return 14;
 BARRIER();return 0;
}
/* Used only after payload finalizers and resident heap have been released. */
static int menu_timer;
static void menu_callback(void)
{r_putkey(4,9,0);r_timer_stop(menu_timer);r_timer_remove(menu_timer);}
static int menu(void)
{
 /* gint draws into its own buffer. Leave an OS-owned return page before
    GetKeyWait suspends in MENU; selecting this icon resumes that wait. */
 r_clear();line(0,"Session closed");line(16,"EXE: select app");
 line(32,"MENU: another app");line(48,"No calculation kept");r_display();
 r_clear_keys();menu_timer=r_timer_install(0,menu_callback,0);
 if(menu_timer<=0)return 0;
 r_timer_start(menu_timer);int col=0,row=0;uint16_t key=0;
 do {r_keywait(&col,&row,0,1,0,&key);} while(col!=3||row!=2);
 /* The callback already removed the one-shot timer. */
 return 1;
}
int main(void)
{
 for(;;){
  FxAppItem item={{0},{0}};int choice=fx_choose(&item,"EXT.PRF","FX / EXT APPS",2);if(!choice)return 1;
  uint16_t path[64];FxLargeProfile profile;fx_path(path,item.id,"EXT.PRF");
  if(choice<0&&!fx_exact(path,&profile,sizeof profile)){
   r_clear();line(0,"No EXT apps found");line(16,"Copy FXAPPS folders");line(48,"EXIT: back");r_display();
   int key=0;while(key!=30002)r_getkey(&key);return 1;
  }
  int result=fx_exact(path,&profile,sizeof profile)?fxlarge_profile_validate(&profile):FXLARGE_BAD_PROFILE;
  if(!result)result=storage_free(profile.min_free_bytes);
  r_clear();line(0,"FX Extended Loader");line(16,"Checking image...");r_display();
  unsigned n=resident_end-resident_begin,bytes=0;Context *c=0;unsigned reason=0;
  if(!result){bytes=(sizeof(Context)+profile.page_capacity*4u+255+n+31)&~31u;c=r_malloc(bytes);if(!c)result=20;}
  if(c){
   for(unsigned i=0;i<sizeof *c+profile.page_capacity*4u;i++)((unsigned char *)c)[i]=0;
   c->profile=profile;c->pages=(uint32_t *)(c+1);
   c->resident_bytes=n;c->allocation_bytes=bytes;
   /* A preflight only: the source runtime still owns its actual allocations. */
   if(profile.guest_ram_bytes){void *guest=r_malloc(profile.guest_ram_bytes);if(!guest)result=FXLARGE_GUEST_RAM_ERROR;else r_free(guest);}
   fx_path(path,item.id,item.id[0]?"IMAGE.BIN":"KHICAS.BIN");
   if(!result)result=scan(c,path);
   if(!result){
    uintptr_t runner=((uintptr_t)(c->pages+profile.page_capacity)+255)&~255u,uncached=runner|0x20000000u;
    for(unsigned i=0;i<n;i+=32)purge(runner+i);
    BARRIER();
    for(unsigned i=0;i<n;i++)BYTE(uncached+i)=resident_begin[i];
    if(resident_fixups[0]>511)result=21;
    for(unsigned i=1;!result&&i<=resident_fixups[0];i++){
     uint32_t off=resident_fixups[i];
     if(off+4>n||(off&3)){result=22;break;}
     uint32_t v=REG(uncached+off);
     if(v<(uintptr_t)resident_begin||v>=(uintptr_t)resident_end){result=23;break;}
     REG(uncached+off)=v-(uintptr_t)resident_begin+uncached;
    }
    BARRIER();
    if(!result){
     line(32,"Starting app...");r_display();
     int (*run)(Context *)=(int(*)(Context *))(uncached+(uintptr_t)resident_main-(uintptr_t)resident_begin);
     result=run(c);reason=c->reason;
     if(c->failure_stage)result=40;
    }
   }
   if(result){r_clear();line(0,"App start failed");hexline(16,"Error ",result);hexline(32,"Stage ",c->failure_stage?c->failure_stage:c->stage);hexline(48,"Status ",c->failure_stage?c->failure_status:c->status);r_display();}
   r_free(c);
  }else{line(32,result==20?"Not enough RAM":result==55?"Storage free failed":"Profile rejected");hexline(48,"Error ",result);r_display();}
  if(result){int key=0;while(key!=30002&&key!=30010)r_getkey(&key);}
  if(reason==2)r_poweroff();
  if(!menu())return 1;
 }
}

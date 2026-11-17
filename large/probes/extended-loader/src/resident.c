#include "probe.h"
Context *map_context=(Context *)(uintptr_t)1;
static uint8_t rd(void *p,uint32_t a){(void)p;return BYTE(a);}
static uint32_t hash(uintptr_t a,unsigned n){uint32_t h=2166136261u;while(n--)h=(h^BYTE(a++))*16777619u;return h;}
static void text(Context *c,const char *s){while(*s&&c->used<sizeof c->log-1)c->log[c->used++]=*s++;}
static void hex(Context *c,uint32_t n){for(int i=7;i>=0;i--){unsigned x=(n>>(4*i))&15;char s[2]={(char)(x<10?'0'+x:'A'+x-10),0};text(c,s);}}
static void event(Context *c,const char *s,uint32_t a,uint32_t b){text(c,s);text(c,"=");hex(c,a);text(c,",");hex(c,b);text(c,"\n");}
static int save(Context *c){int f=r_open(c->log_path,2,0);if(f<0)return 0;int n=r_write(f,c->log,c->used),rc=r_close(f);return n==(int)c->used&&rc>=0;}
static void clear_window(void)
{
 for(unsigned i=0;i<64;i++){uint32_t a=0xf6000000u+(i<<8);uint32_t va=REG(a)&~4095u;
  if(va>=BASE&&va<BASE+PAGES*4096){REG(a)=0;REG(a+0x1000000)=0;}}
 for(unsigned i=0;i<4;i++){REG(0xf2000000u+(i<<8))=0;REG(0xf3000000u+(i<<8))=0;}
 BARRIER();
}
/* Bounded, allocation-free refill. No Bfile or host-assisted mapping here. */
void resident_refill(uint32_t address)
{
 Context *c=map_context;
 if(address<BASE||address>=BASE+IMAGE_BYTES){c->fault=address;for(;;)__asm__ volatile("nop");}
 unsigned page=(address-BASE)>>12;uint32_t physical=c->pages[page];
 if(!physical){c->fault=address;for(;;)__asm__ volatile("nop");}
 unsigned slot=c->slot;c->slot=(slot+1)&7u;
 REG(0xff000000)=address&~4095u;REG(0xff000004)=physical|0x15cu;
 REG(0xff000034)=0;REG(0xff000010)=(REG(0xff000010)&~0xfc00u)|(slot<<10);
 __asm__ volatile("ldtlb":::"memory");BARRIER();
 c->refills++;if(page>=512)c->high_refills++;
}
static int scan(Context *c)
{
 int f=r_open(c->bin_path,1,0);if(f<0)return 1;
 if(r_size(f)!=IMAGE_BYTES){r_close(f);return 2;}
 unsigned fragments=0;uint32_t last=0;
 for(unsigned p=0;p<PAGES;p++){
  uint32_t pa=0;int span=((int(*)(int,int,uint32_t *))(uintptr_t)c->os.query)(f,p*4096,&pa);pa&=0x1fffffffu;
  if(span!=4096||(pa&4095)||pa<0x10000||pa>0x1fff000u){r_close(f);return 3;}
  unsigned bytes=IMAGE_BYTES-p*4096;if(bytes>4096)bytes=4096;
  uint32_t h=2166136261u;
  for(unsigned off=0;off<bytes;off+=sizeof c->buffer){
   unsigned n=bytes-off;if(n>sizeof c->buffer)n=sizeof c->buffer;
   if(r_read(f,c->buffer,n,p*4096+off)!=(int)n){r_close(f);return 4;}
   for(unsigned j=0;j<n;j++)h=(h^c->buffer[j])*16777619u;
  }
  if(h!=hash(pa|0xa0000000u,bytes)){r_close(f);return 5;}
  if(c->hashes[p]&&c->hashes[p]!=h){r_close(f);return 6;}
  c->pages[p]=pa;c->hashes[p]=h;if(p&&pa!=last+4096)fragments++;last=pa;
 }
 c->fragmented=fragments;return r_close(f)<0?7:0;
}
static int refresh(Context *c)
{
 int f=r_open(c->bin_path,1,0);if(f<0)return 1;
 if(r_size(f)!=IMAGE_BYTES){r_close(f);return 2;}
 for(unsigned p=0;p<PAGES;p++){
  uint32_t pa=0;int span=((int(*)(int,int,uint32_t *))(uintptr_t)c->os.query)(f,p*4096,&pa);pa&=0x1fffffffu;
  if(span!=4096||(pa&4095)||pa<0x10000||pa>0x1fff000u){r_close(f);return 3;}
  if(pa!=c->pages[p]){
   unsigned n=IMAGE_BYTES-p*4096;if(n>4096)n=4096;
   if(hash(pa|0xa0000000u,n)!=c->hashes[p]){r_close(f);return 4;}
   c->pages[p]=pa;
  }
 }
 return r_close(f)<0?5:0;
}
static void enter(Context *c)
{
 c->sr=sr_get();sr_set(c->sr|0xf0);
 c->vbr=vbr_get();c->mmucr=REG(0xff000010);c->pteh=REG(0xff000000);c->ptel=REG(0xff000004);c->ptea=REG(0xff000034);c->cursor=REG(c->os.cursor);
 for(unsigned i=0;i<512;i++){c->original[i]=REG(c->os.pages+4*i);if(!c->mode)REG(c->os.pages+4*i)=c->pages[i];}
 clear_window();c->slot=0;
 if(c->mode==2)vbr_set((uintptr_t)map_vectors);
 BARRIER();
}
static void leave(Context *c)
{
 vbr_set(c->vbr);for(unsigned i=0;i<512;i++)REG(c->os.pages+4*i)=c->original[i];
 REG(c->os.cursor)=c->cursor;clear_window();
 REG(0xff000000)=c->pteh;REG(0xff000004)=c->ptel;REG(0xff000034)=c->ptea;REG(0xff000010)=c->mmucr;
 BARRIER();sr_set(c->sr);
}
static int execute(Context *c,unsigned round)
{
 /* 73 is coprime to 698; every page is revisited in a different order. */
 for(unsigned k=0;k<PAGES;k++){
  unsigned p=round?(k*73+511)%PAGES:c->mode==2?(k+512)%PAGES:k;
  uintptr_t va=BASE+p*4096;unsigned bytes=IMAGE_BYTES-p*4096;if(bytes>4096)bytes=4096;
  if(c->mode==1)resident_refill(va);
  if(hash(va,bytes)!=c->hashes[p])return 10;
  c->verified++;
  uint32_t value=((uint32_t(*)(void))(va+32))();
  if(value!=(0x69800000u|p))return 11;
  c->calls++;
  if(round==2){
   unsigned other=(p+349)%PAGES;
   if(c->mode==1)resident_refill(BASE+other*4096);
   value=((uint32_t(*)(void))(va+64))();
   if(value!=(0x69800000u|other))return 12;
   c->cross_calls++;
  }
 }
 return 0;
}
int resident_main(Context *c)
{
 map_context=c;text(c,"MAP698 / emulator experiment\n");event(c,"MODE_BYTES",c->mode,IMAGE_BYTES);
 event(c,"ALLOC_RESIDENT",c->allocation_bytes,c->resident_bytes);
 event(c,"CAS_RESERVE_PAGES",32768,PAGES);
 c->failed=fx_os_profile(rd,0,&c->os);event(c,"OS_PROFILE",c->failed,c->os.pages);if(c->failed){save(c);return c->failed;}
 c->failed=scan(c);event(c,"SCAN",c->failed,c->fragmented);if(!save(c)||c->failed)return 20;
 /* Refresh after writing the log, before borrowing or replacing mappings. */
 c->failed=refresh(c);if(c->failed)return c->failed;
 for(unsigned round=0;round<3;round++){
  c->before_hash=hash(c->os.pages,2052);
  enter(c);c->failed=execute(c,round);leave(c);
  c->after_hash=hash(c->os.pages,2052);
  event(c,"ROUND_CALLS",round,c->calls);event(c,"REFILLS_HIGH",c->refills,c->high_refills);
  event(c,"OS_TABLE_RESTORED",c->before_hash,c->after_hash);
  if(c->before_hash!=c->after_hash)c->failed=21;
  if(c->failed){event(c,"FAILED",c->failed,c->fault);save(c);return c->failed;}
  if(!save(c))return 22;
  if(round<2){c->failed=refresh(c);if(c->failed)return c->failed;}
 }
 event(c,"CROSS_CALLS",c->cross_calls,0);
 event(c,"PASS",c->calls,c->verified);return save(c)?0:23;
}

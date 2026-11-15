#include "loader.h"
Context *resident_context=(Context *)(uintptr_t)1;
void log_text(Context *c,const char *s)
{while(*s&&c->log_used<LOG_BYTES-1)c->log[c->log_used++]=*s++;if(*s)c->failed|=0x100;}
static void hex(Context *c,uint32_t n)
{for(int i=7;i>=0;i--){unsigned v=(n>>(i*4))&15;char b[2]={(char)(v<10?'0'+v:'A'+v-10),0};log_text(c,b);}}
void log_event(Context *c,const char *name,uint32_t a,uint32_t b)
{log_text(c,name);log_text(c,"=");hex(c,a);log_text(c,",");hex(c,b);log_text(c,"\n");}
int log_save(Context *c)
{
 for(unsigned i=c->log_used;i<LOG_BYTES;i++)c->log[i]=' ';
 int fd=r_open(c->log_path,2,0);if(fd<0)return 0;
 int n=r_write(fd,c->log,LOG_BYTES),rc=r_close(fd);
 if(n!=LOG_BYTES||rc<0){c->failed|=0x200;return 0;}
 char tail[32];unsigned count=c->log_used<32?c->log_used:32;
 fd=r_open(c->log_path,1,0);if(fd<0)return 0;
 n=r_read(fd,tail,count,c->log_used-count);rc=r_close(fd);
 if(n!=(int)count||rc<0)return 0;
 for(unsigned i=0;i<count;i++)if(tail[i]!=c->log[c->log_used-count+i])return 0;
 return 1;
}
static unsigned page_size(uint32_t d)
{unsigned n=((d>>6)&2)|((d>>4)&1);return n==0?1024:n==1?4096:n==2?65536:1048576;}
static int overlaps(Context *c,uint32_t a,uint32_t d)
{unsigned size=page_size(d);uint32_t start=a&~(size-1);return start<BASE+c->mapped_bytes&&(uint64_t)start+size>BASE;}
static void drop_itlb(Context *c)
{for(unsigned i=0;i<4;i++){uintptr_t a=0xf2000000+(i<<8),d=0xf3000000+(i<<8);if(overlaps(c,REG(a),REG(d))){REG(a)&=~0x100u;REG(d)&=~0x100u;}}BARRIER();}
static unsigned guard(Context *c)
{
 if(!c->active)return 0;
 unsigned bad=0;
 for(unsigned i=0;i<c->pages;i++){
  unsigned slot=c->reserve+i;
  uint32_t a=REG(0xf6000000+(slot<<8)),d=REG(0xf7000000+(slot<<8));
  if((a&0xfffffd00)!=(BASE+i*4096+0x100)||(d&0x1ffffdff)!=((c->image+i*4096)&0x1fffffff)+0x17e)bad++;
 }
 if(((REG(0xff000010)>>18)&63)!=c->reserve)bad|=0x10000;
 return bad;
}
static int install(Context *c)
{
 uint32_t sr=sr_get();sr_set(sr|0xf0);BARRIER();
 c->mmucr=REG(0xff000010);c->pteh=REG(0xff000000);c->ptel=REG(0xff000004);c->ptea=REG(0xff000034);
 unsigned bound=(c->mmucr>>18)&63;if(!bound)bound=64;
 if(!(c->mmucr&1)||(c->mmucr&0x80)||c->pages+8>bound){sr_set(sr);return 0;}
 c->reserve=bound-c->pages;
 for(unsigned i=0;i<64;i++){
  c->old[i]=(Entry){REG(0xf6000000+(i<<8)),REG(0xf7000000+(i<<8)),REG(0xf7800000+(i<<8))};
  c->touched[i]=0;
 }
 c->active=1;
 for(unsigned i=0;i<64;i++)if((c->old[i].addr&0x100)&&overlaps(c,c->old[i].addr,c->old[i].data)){
  c->touched[i]=1;REG(0xf6000000+(i<<8))&=~0x100u;REG(0xf7000000+(i<<8))&=~0x100u;
 }
 drop_itlb(c);
 uint32_t control=(c->mmucr&~0xfcfc00u)|(c->reserve<<18);
 for(unsigned i=0;i<c->pages;i++){
  unsigned slot=c->reserve+i;c->touched[slot]=1;
  REG(0xff000000)=BASE+i*4096+(c->pteh&255);
  REG(0xff000004)=((c->image+i*4096)&0x1fffffff)|0x17e;
  REG(0xff000034)=0;REG(0xff000010)=control|(slot<<10);
  __asm__ volatile("ldtlb":::"memory");BARRIER();
 }
 REG(0xff000010)=control;BARRIER();unsigned bad=guard(c);sr_set(sr);BARRIER();
 log_event(c,"MAPPING_INSTALLED",c->pages,bad);if(bad)c->failed|=1;return !bad;
}
static void restore(Context *c)
{
 if(!c->active)return;
 uint32_t sr=sr_get();sr_set(sr|0xf0);BARRIER();drop_itlb(c);
 unsigned bad=0;
 for(unsigned i=0;i<64;i++)if(c->touched[i]){
  REG(0xf6000000+(i<<8))=0;REG(0xf7000000+(i<<8))=c->old[i].data;
  REG(0xf7800000+(i<<8))=c->old[i].ext;REG(0xf6000000+(i<<8))=c->old[i].addr;
  if(REG(0xf6000000+(i<<8))!=c->old[i].addr||REG(0xf7000000+(i<<8))!=c->old[i].data||REG(0xf7800000+(i<<8))!=c->old[i].ext)bad++;
 }
 REG(0xff000000)=c->pteh;REG(0xff000004)=c->ptel;REG(0xff000034)=c->ptea;
 REG(0xff000010)=c->mmucr;BARRIER();c->active=0;sr_set(sr);BARRIER();
 REG(0x08100000)=c->ram_word;
 log_event(c,"MAPPING_RESTORED",bad,REG(0xff000010));if(bad)c->failed|=2;
}
int resident_register_quit(void (*callback)(void))
{Context *c=resident_context;c->guest_quit=(uintptr_t)callback;log_event(c,"TARGET_QUIT_REGISTERED",c->guest_quit,0);return 0;}
static void target_quit(Context *c)
{
 unsigned bad=guard(c);log_event(c,"TARGET_EXIT_GUARD",bad,c->guest_quit);
 if(bad){c->failed|=4;return;}
 uintptr_t callback=c->guest_quit;c->guest_quit=0;
 if(callback){((void (*)(void))callback)();log_text(c,"TARGET_CALLBACK_RETURNED\n");}
}
void resident_quit_work(Context *c)
{
 if(c->in_callback)return;
 c->in_callback=1;c->quit_seen++;
 log_event(c,"OS_CALLBACK",c->active,c->quit_seen);
 target_quit(c);restore(c);log_event(c,"CLEANUP",c->failed,c->quit_seen);log_save(c);
}
int resident_main(Context *c)
{
 resident_context=c;c->ram_word=REG(0x08100000);
 log_text(c,"HANDOFF_PENDING\n");if(!log_save(c))return -1;
 r_quit(resident_quit_entry);
 if(!install(c)){restore(c);r_quit(0);log_text(c,"FAIL_MAPPING\n");log_save(c);return -2;}
 log_text(c,"TARGET_ENTER\n");if(!log_save(c)){restore(c);r_quit(0);return -3;}
 c->result=((int (*)(int,int))c->entry)(1,0);
 log_event(c,"TARGET_RETURN",c->result,guard(c));
 target_quit(c);restore(c);r_quit(0);log_event(c,"CLEANUP",c->failed,0);log_save(c);
 return c->failed?-4:0;
}

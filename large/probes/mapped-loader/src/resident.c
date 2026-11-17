#include "loader.h"
Context *resident_context=(Context *)(uintptr_t)1;
static uint8_t rom_read(void *u,uint32_t a){(void)u;return BYTE(a);}
static unsigned page_size(uint32_t d){unsigned x=((d>>6)&2)|((d>>4)&1);return x==0?1024:x==1?4096:x==2?65536:1048576;}
static int overlap(uint32_t a,uint32_t d)
{unsigned sz=page_size(d);uint32_t va=a&~(sz-1);return (uint64_t)va<0x00500000u&&(uint64_t)va+sz>BASE;}
static void flush_window(void)
{
 for(unsigned i=0;i<64;i++){uint32_t a=0xf6000000u+(i<<8),d=0xf7000000u+(i<<8);if(overlap(REG(a),REG(d))){REG(a)&=~0x100u;REG(d)&=~0x100u;}}
 for(unsigned i=0;i<4;i++){uint32_t a=0xf2000000u+(i<<8),d=0xf3000000u+(i<<8);if(overlap(REG(a),REG(d))){REG(a)&=~0x100u;REG(d)&=~0x100u;}}
 BARRIER();
}
static uint32_t mapped(Context *c,unsigned i)
{if(i==0)return c->shadow&0x1fffffff;if(i==465)return (c->shadow+4096)&0x1fffffff;if(i==470)return (c->shadow+8192)&0x1fffffff;if(i==471)return (c->shadow+12288)&0x1fffffff;return c->pages[i];}
static unsigned guard(Context *c)
{unsigned diff=0;for(unsigned i=0;i<512;i++)diff+=REG(c->os.pages+4*i)!=mapped(c,i);return diff;}
static void snapshot(Context *c)
{for(unsigned i=0;i<512;i++)c->original[i]=REG(c->os.pages+i*4);c->old_cursor=REG(c->os.cursor);c->mmucr=REG(0xff000010);c->pteh=REG(0xff000000);c->ptel=REG(0xff000004);c->ptea=REG(0xff000034);}
static void install(Context *c)
{
 uint32_t sr=sr_get();sr_set(sr|0xf0);BARRIER();
 for(unsigned i=0;i<512;i++)REG(c->os.pages+i*4)=mapped(c,i);
 REG(c->os.cursor)=0;flush_window();c->active=1;sr_set(sr);BARRIER();
}
static void restore(Context *c)
{
 if(!c->active)return;
 uint32_t sr=sr_get();sr_set(sr|0xf0);BARRIER();
 for(unsigned i=0;i<512;i++)REG(c->os.pages+i*4)=c->original[i];
 REG(c->os.cursor)=c->old_cursor;flush_window();
 REG(0xff000000)=c->pteh;REG(0xff000004)=c->ptel;REG(0xff000034)=c->ptea;REG(0xff000010)=c->mmucr;
 BARRIER();c->active=0;sr_set(sr);BARRIER();
}
static int address(Context *c,int fd,unsigned offset,uint32_t *out)
{return ((int(*)(int,int,uint32_t *))(uintptr_t)c->os.query)(fd,offset,out);}
static void text(Context *c,const char *s)
{while(*s&&c->log_used<LOG_BUFFER-1)c->log[c->log_used++]=*s++;}
static void hex(Context *c,uint32_t n)
{for(int k=7;k>=0;k--){unsigned d=(n>>(k*4))&15;if(c->log_used<LOG_BUFFER-1)c->log[c->log_used++]=(char)(d<10?'0'+d:'A'+d-10);}}
static void event(Context *c,const char *s,uint32_t a,uint32_t b)
{text(c,s);text(c,"=");hex(c,a);text(c,",");hex(c,b);text(c,"\n");}
static uint32_t hash(uintptr_t p,unsigned n)
{uint32_t h=2166136261u;while(n--)h=(h^BYTE(p++))*16777619u;return h;}
static int save(Context *c)
{
 if(c->io_error||!c->log_used)return !c->io_error;
 unsigned n=(c->log_used+511)&~511u;
 if(c->log_saved+n>LOG_BYTES){c->io_error=1;return 0;}
 for(unsigned i=c->log_used;i<n;i++)c->log[i]=' ';
 c->file_busy++;
 int fd=r_open(c->log_path,2,0),rc=-1,got=-1;
 if(fd>=0){if(r_seek(fd,c->log_saved)>=0)got=r_write(fd,c->log,n);rc=r_close(fd);}
 c->file_busy--;
 if(got!=(int)n||rc<0){c->io_error=1;return 0;}
 c->log_saved+=n;c->log_used=0;return 1;
}
static int start_log(Context *c)
{
 char b[8];int fd=r_open(c->log_path,1,0);if(fd<0)return 0;
 int ok=r_size(fd)==LOG_BYTES&&r_read(fd,b,8,0)==8;
 if(r_close(fd)<0)ok=0;
 const char *magic="FXKLOAD1";for(unsigned i=0;i<8;i++)if(b[i]!=magic[i])ok=0;
 if(!ok)return 0;
 text(c,"FXKLOAD1\nBUILD=0.1\n");
 /* Clear old results only after validating the dedicated result file. */
 for(unsigned i=0;i<LOG_BUFFER;i++)c->log[i]=' ';
 fd=r_open(c->log_path,2,0);if(fd<0)return 0;
 for(unsigned i=0;i<LOG_BYTES;i+=LOG_BUFFER)if(r_write(fd,c->log,LOG_BUFFER)!=LOG_BUFFER)ok=0;
 if(r_close(fd)<0)ok=0;
 c->log_used=0;text(c,"FXKLOAD1\nBUILD=0.1\n");return ok;
}
/* File queries stay in P2. Never call Bfile from a TLB fault or timer.
 * Refresh the Loader's own pages too: file operations can move either file. */
static int refresh(Context *c)
{
 c->file_busy++;int ok=1;
 int fd=r_open(c->self_path,1,0);
 if(fd<0){c->file_busy--;return 0;}
 int size=r_size(fd);
 if(size<512||size>65536||(c->self_bytes&&c->self_bytes!=(unsigned)size))ok=0;
 for(unsigned i=0;ok&&i<((unsigned)size+4095)/4096;i++){
  uint32_t a=0;int span=address(c,fd,i*4096,&a);uint32_t pa=a&0x1fffffff;
  if(span!=4096||(pa&4095)||pa<0x10000||pa>0x1fff000){ok=0;break;}
  if(!c->self_bytes){
   unsigned n=size-i*4096;if(n>4096)n=4096;
   if(hash(pa|0xa0000000u,n)!=hash(BASE+i*4096,n)){ok=0;break;}
  }
  c->original[i]=pa;
 }
 if(r_close(fd)<0)ok=0;
 if(!ok){c->file_busy--;return 0;}
 c->self_bytes=size;
 fd=r_open(c->bin_path,1,0);if(fd<0){c->file_busy--;return 0;}
 if(r_size(fd)!=IMAGE_BYTES)ok=0;
 for(unsigned i=0;i<512&&ok;i++){
  uint32_t a=0;int span=address(c,fd,i*4096,&a);uint32_t pa=a&0x1fffffff;
  if(span!=4096||(pa&4095)||pa<0x10000||pa>0x1fff000){ok=0;break;}
  if(c->pages[i]!=pa){
   unsigned n=IMAGE_BYTES-i*4096;if(n>4096)n=4096;
   if(hash(pa|0xa0000000u,n)!=c->hashes[i]){ok=0;break;}
   c->changed++;c->pages[i]=pa;
  }
 }
 if(r_close(fd)<0)ok=0;
 c->refreshes++;c->file_busy--;return ok;
}
static int shadows(Context *c)
{
 static const unsigned pages[]={0,465,470,471};
 for(unsigned k=0;k<4;k++){
  uintptr_t dst=c->shadow+k*4096;
  for(unsigned j=0;j<4096;j+=32){purge(dst+j);}
  BARRIER();
  for(unsigned j=0;j<4096;j++)BYTE((dst|0x20000000u)+j)=BYTE((c->pages[pages[k]]|0xa0000000u)+j);
 }
 for(unsigned i=0;i<c->profile.count;i++){
  Patch *p=&c->profile.patches[i];
  if((p->offset&3)||p->offset+4>IMAGE_BYTES||(i&&c->profile.patches[i-1].offset>=p->offset))return 0;
  unsigned k=0;while(k<4&&pages[k]!=p->offset/4096)k++;if(k==4)return 0;
  uintptr_t dst=(c->shadow+k*4096+(p->offset&4095))|0x20000000u;
  if(REG(dst)!=p->expected)return 0;
  uint32_t value=p->value;
  if(p->expected==0x80010070u&&value==0)value=(uintptr_t)resident_gateway;
  else if(!((p->offset==0x1d14d0&&p->expected==0x88051000u&&value==0x88060000u)||
            (p->offset==0x1d14dc&&p->expected==0x88052000u&&value==0x88061000u)||
            (p->offset==0x1d14f0&&p->expected==0x88053800u&&value==0x88062800u)))return 0;
  REG(dst)=value;
 }
 BARRIER();return 1;
}
static void stop_timers(Context *c)
{for(unsigned i=0;i<10;i++)if(c->timers[i].id>0){r_timer_stop(c->timers[i].id);r_timer_remove(c->timers[i].id);c->timers[i].id=0;}}
static void fatal(Context *c,unsigned code)
{
 c->failed=code;stop_timers(c);r_quit(0);
 event(c,"RUNTIME_FAILED",code,c->last_syscall);save(c);
 /* Never return into target code after an unverified page lookup. */
 r_reset();for(;;){}
}
static void timer(Context *c,unsigned slot)
{
 if(!c->active||c->file_busy||c->in_callback||guard(c)){c->timer_skipped++;return;}
 uintptr_t fn=c->timers[slot].callback;
 if(fn>=BASE+512&&fn<BASE+IMAGE_BYTES){c->timer_calls++;((void(*)(void))fn)();}
}
#define TIMER(n) static void timer##n(void){timer(resident_context,n);}
TIMER(0) TIMER(1) TIMER(2) TIMER(3) TIMER(4) TIMER(5) TIMER(6) TIMER(7) TIMER(8) TIMER(9)
static const uintptr_t callbacks[]={(uintptr_t)timer0,(uintptr_t)timer1,(uintptr_t)timer2,(uintptr_t)timer3,(uintptr_t)timer4,(uintptr_t)timer5,(uintptr_t)timer6,(uintptr_t)timer7,(uintptr_t)timer8,(uintptr_t)timer9};
_Static_assert(sizeof(Frame)==56&&offsetof(Frame,sp)==40,"gateway frame ABI");
void resident_dispatch(Frame *f)
{
 Context *c=resident_context;unsigned n=f->r[0];c->syscalls++;c->last_syscall=n;
 if(n==0x494){c->guest_quit=f->r[4];f->r[0]=0;return;}
 /* Reviewed file operations and GetKey can disturb mappings or relocate files.
  * Ordinary drawing/key-state/tick syscalls do not trigger a 512-page rescan. */
 unsigned file=(n>=0x42b&&n<=0x46f)||(n>=0x1d0&&n<=0x21f);
 int slot=-1;unsigned timer_id=f->r[4];
 if(n==0x118){
  for(unsigned i=0;i<10;i++)if(!c->timers[i].id){slot=i;break;}
  if(slot<0||f->r[5]<BASE+512||f->r[5]>=BASE+IMAGE_BYTES)fatal(c,10);
  c->timers[slot].callback=f->r[5];f->r[5]=callbacks[slot];
 }
 if(n==0x90f&&c->key_calls++==0){
  event(c,"TARGET_GETKEY",f->pr,c->guest_quit);save(c);
  if(!refresh(c)){fatal(c,11);}
  install(c);
 }
 if(file)c->file_busy++;
 resident_os_call(f);
 if(file)c->file_busy--;
 if(slot>=0){
  if(f->r[5]==callbacks[slot])f->r[5]=c->timers[slot].callback;
  c->timers[slot].id=(int)f->r[0]>0?(int)f->r[0]:0;
 }
 if(n==0x119)for(unsigned i=0;i<10;i++)if(c->timers[i].id==(int)timer_id)c->timers[i].id=0;
 if(file||n==0x90f){
  if(!refresh(c)){fatal(c,12);}
  install(c);
 }else if(guard(c)){
  if(!refresh(c)){fatal(c,13);}
  install(c);
 }
}
static void cleanup(Context *c)
{
 if(c->in_callback)return;
 c->in_callback=1;
 stop_timers(c);
 event(c,"CLEANUP_BEGIN",c->guest_quit,c->last_syscall);
 /* Menu activity may have moved the file before the callback was entered. */
 if(c->active){
  if(!refresh(c)){fatal(c,14);}
  install(c);
  uintptr_t fn=c->guest_quit;c->guest_quit=0;
  if(fn){if(fn<BASE+512||fn>=BASE+IMAGE_BYTES)fatal(c,15);((void(*)(void))fn)();}
 }
 stop_timers(c);
 event(c,"TARGET_CLEANUP_DONE",c->syscalls,c->key_calls);
 event(c,"REFRESH_CHANGED",c->refreshes,c->changed);
 event(c,"TIMER_CALLS_SKIPPED",c->timer_calls,c->timer_skipped);
 event(c,"RESTORE_PENDING",0,0);
 save(c);
 if(!refresh(c))fatal(c,16);
 restore(c);REG(0x08100000)=c->ram_word;BARRIER();
}
void resident_quit_work(Context *c){cleanup(c);}
int resident_main(Context *c)
{
 resident_context=c;
 if(!start_log(c))return 1;
 uint32_t sp;__asm__ volatile("mov r15,%0":"=r"(sp));
 event(c,"CONTEXT_BYTES",(uintptr_t)c,c->allocation_bytes);
 event(c,"RESIDENT_BYTES",c->resident,c->runner_bytes);event(c,"SHADOW_STACK",c->shadow,sp);
 if(REG(0xff000030)!=0x10300b00||REG(0xff000044)!=0x2c00||(sp&0xe0000000)!=0x80000000u){event(c,"FAIL_CPU_STACK",sp,0);save(c);return 2;}
 int result=fx_os_profile(rom_read,0,&c->os);event(c,"OS_PROFILE",result,c->os.query);
 if(result||!(REG(0xff000010)&1)||!BYTE(c->os.enabled)||REG(c->os.cursor)>54){text(c,"FAIL_OS_MAP\n");save(c);return 3;}
 snapshot(c);text(c,"VERIFY_MAP_PENDING\n");if(!save(c))return 4;
 if(!refresh(c)||!shadows(c)){text(c,"FAIL_MAP_OR_PATCH\n");save(c);return 5;}
 event(c,"READY_ENTRY",BASE+512,WORK_BASE);if(!save(c)||!refresh(c))return 6;
 r_quit(resident_quit_entry);install(c);
 static const unsigned shadow_pages[]={0,465,470,471};
 for(unsigned k=0;k<4;k++)for(unsigned j=0;j<4096;j+=32)invalidate(BASE+shadow_pages[k]*4096+j);
 BARRIER();
 int target_result=((int(*)(int,int))(uintptr_t)(BASE+512))(1,0);
 event(c,"TARGET_RETURNED",target_result,0);cleanup(c);r_quit(0);return c->failed||c->io_error;
}

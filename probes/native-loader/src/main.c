#include "loader.h"
void *memcpy(void *out,const void *in,size_t n)
{unsigned char *d=out;const unsigned char *s=in;for(size_t i=0;i<n;i++)d[i]=s[i];return out;}
void *memset(void *out,int value,size_t n)
{unsigned char *d=out;for(size_t i=0;i<n;i++)d[i]=(unsigned char)value;return out;}
typedef struct {char id[8],title[16];} Item;
typedef struct {char magic[8];uint32_t count;Item item[8];} Catalog;
static void wide(uint16_t *out,const char *in){while(*in)*out++=(unsigned char)*in++;*out=0;}
static int equal(const void *av,const void *bv,unsigned n){const unsigned char *a=av,*b=bv;for(unsigned i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static void zero(void *pv,unsigned n){unsigned char *p=pv;while(n--)*p++=0;}
static int p1(void *p){return ((uintptr_t)p&0xe0000000)==0x80000000;}
static uintptr_t align(void *p,unsigned n){return ((uintptr_t)p+n-1)&~(uintptr_t)(n-1);}
static void path(uint16_t *p,const char *id,const char *suffix)
{char out[32]="\\\\fls0\\";unsigned n=7;for(unsigned i=0;id[i]&&i<8;i++)out[n++]=id[i];while(*suffix)out[n++]=*suffix++;out[n]=0;wide(p,out);}
static void show(const char *a,const char *b)
{r_clear();r_print(0,0,(const unsigned char *)"Hot Loader 0.1",0);r_print(0,19,(const unsigned char *)a,0);r_print(0,33,(const unsigned char *)b,0);r_print(0,53,(const unsigned char *)"EXIT: menu",0);r_display();}
static int exact(const uint16_t *path,void *out,unsigned bytes)
{int fd=r_open(path,1,0);if(fd<0)return 0;int n=r_size(fd)==(int)bytes?r_read(fd,out,bytes,0):-1,rc=r_close(fd);return n==(int)bytes&&rc>=0;}
static int choose(Item *selected)
{
 Catalog cat;uint16_t filename[32];wide(filename,"\\\\fls0\\Loader.idx");
 if(!exact(filename,&cat,sizeof cat)||!equal(cat.magic,"FXLDIDX1",8)||!cat.count||cat.count>8)return -1;
 for(unsigned i=0;i<cat.count;i++){
  if(!cat.item[i].id[0]||cat.item[i].id[7]||cat.item[i].title[15])return -1;
  for(unsigned j=0;cat.item[i].id[j];j++){char x=cat.item[i].id[j];if(!((x>='a'&&x<='z')||(x>='0'&&x<='9')||x=='_'))return -1;}
 }
 unsigned current=0;
 for(;;){
  r_clear();r_print(0,0,(const unsigned char *)"Hot Loader 0.1",0);
  for(unsigned i=0;i<cat.count&&i<4;i++){unsigned k=(current/4)*4+i;if(k>=cat.count)break;r_print(0,12+10*i,(const unsigned char *)(k==current?">":" "),0);r_print(8,12+10*i,(const unsigned char *)cat.item[k].title,0);}
  r_print(0,54,(const unsigned char *)"UP/DN EXE  EXIT",0);r_display();
  int key=0;r_getkey(&key);
  if(key==30002)return 0;
  if(key==30018)current=(current+cat.count-1)%cat.count;
  if(key==30023)current=(current+1)%cat.count;
  if(key==30004){*selected=cat.item[current];return 1;}
 }
}
static void release(Context *c){if(c->runner_allocation)r_free(c->runner_allocation);if(c->image_allocation)r_free(c->image_allocation);r_free(c);}
static void finalize(Context *c){r_quit(0);release(c);}
static int log_open(Context *c)
{
 wide(c->log_path,"\\\\fls0\\Loader.txt");int fd=r_open(c->log_path,1,0);
 if(fd>=0){char magic[8];int size=r_size(fd),n=r_read(fd,magic,8,0),rc=r_close(fd);return size==LOG_BYTES&&n==8&&rc>=0&&equal(magic,"FXLOADER",8);}
 if(fd!=-1)return 0;
 int size=LOG_BYTES;return r_create(c->log_path,1,&size)>=0;
}
int main(void)
{
 Item item;int choice=choose(&item);if(!choice)return 1;
 if(choice<0){show("Bad/missing catalog","Need Loader.idx");int key=0;while(key!=30002)r_getkey(&key);return 1;}
 Context *c=r_malloc(sizeof *c);
 if(!c){show("No context memory","Target not started");int key=0;while(key!=30002)r_getkey(&key);return 1;}
 if(!p1(c)){r_free(c);show("Unsupported heap","Target not started");int key=0;while(key!=30002)r_getkey(&key);return 1;}
 zero(c,sizeof *c);c->finalize=finalize;
 const char *problem="Unknown failure";
 if(!log_open(c)){release(c);show("Log file protected","Keep Loader.txt");int key=0;while(key!=30002)r_getkey(&key);return 1;}
 log_text(c,"FXLOADER\nVersion=1\nTARGET=");log_text(c,item.id);log_text(c,"\n");
 log_event(c,"ALLOC_CONTEXT",sizeof *c,(uintptr_t)c);log_save(c);
 Profile profile;uint16_t filename[32];path(filename,item.id,".lpf");
 if(!exact(filename,&profile,sizeof profile)){problem="Profile read/size";goto failed;}
 if(!equal(profile.magic,"FXLDP001",8)||profile.version!=1||profile.bytes<516||profile.bytes>0x400000||profile.entry<BASE+512||profile.entry>=BASE+profile.bytes||(profile.entry&1)||profile.flags!=1||profile.patch_count>MAX_PATCHES||profile.forbid_count>8){problem="Profile invalid";goto failed;}
 for(unsigned i=0;i<profile.patch_count;i++)if(profile.patches[i]<512||(profile.patches[i]&3)||profile.patches[i]>profile.bytes-4||(i&&profile.patches[i]<=profile.patches[i-1])){problem="Profile patch range";goto failed;}
 for(unsigned i=0;i<profile.forbid_count;i++)if(profile.forbidden[i][0]>=profile.forbidden[i][1]||(profile.forbidden[i][0]&0xe0000000)!=0x80000000||(profile.forbidden[i][1]&0xe0000000)!=0x80000000){problem="Profile RAM range";goto failed;}
 c->image_bytes=profile.bytes;c->mapped_bytes=(profile.bytes+4095)&~4095u;c->pages=c->mapped_bytes/4096;c->entry=profile.entry;c->flags=profile.flags;
 log_event(c,"IMAGE_BYTES_PAGES",c->image_bytes,c->pages);
 if(c->mapped_bytes>MAX_IMAGE){problem="Need file mapping";goto failed;}
 unsigned bytes=resident_end-resident_begin;
 c->image_allocation=r_malloc(c->mapped_bytes+8191);
 log_event(c,"ALLOC_IMAGE",c->mapped_bytes+8191,(uintptr_t)c->image_allocation);
 if(!c->image_allocation){problem="No image memory";goto failed;}
 if(!p1(c->image_allocation)){problem="Image not P1";goto failed;}
 c->runner_allocation=r_malloc(bytes+32);
 log_event(c,"ALLOC_RUNNER",bytes+32,(uintptr_t)c->runner_allocation);
 if(!c->runner_allocation){problem="No runner memory";goto failed;}
 if(!p1(c->runner_allocation)){problem="Runner not P1";goto failed;}
 c->image=align(c->image_allocation,8192);uintptr_t runner=align(c->runner_allocation,32);c->resident=runner|0x20000000;
 for(unsigned i=0;i<profile.forbid_count;i++){
  uintptr_t lo=profile.forbidden[i][0],hi=profile.forbidden[i][1];
  if(((uintptr_t)c<hi&&(uintptr_t)c+sizeof *c>lo)||(c->image<hi&&c->image+c->mapped_bytes>lo)||(runner<hi&&runner+bytes>lo)){problem="Target RAM conflict";goto failed;}
 }
 path(filename,item.id,".bin");int fd=r_open(filename,1,0);
 if(fd<0){problem="Missing BIN";goto failed;}
 if(r_size(fd)!=(int)c->image_bytes){r_close(fd);problem="BIN size mismatch";goto failed;}
 Sha256 hash;sha_init(&hash);int read_ok=1;
 for(unsigned off=0;off<c->image_bytes;){unsigned n=c->image_bytes-off;if(n>4096)n=4096;
  if(r_read(fd,(void *)(c->image+off),n,off)!=(int)n){read_ok=0;break;}
  sha_update(&hash,(const unsigned char *)(c->image+off),n);off+=n;
 }
 int rc=r_close(fd);unsigned char digest[32];sha_final(&hash,digest);
 if(!read_ok||rc<0){problem="BIN read failed";goto failed;}
 if(!equal(digest,profile.sha256,32)){problem="BIN hash mismatch";goto failed;}
 log_text(c,"SHA256_OK\n");
 for(unsigned i=c->image_bytes;i<c->mapped_bytes;i++)((unsigned char *)c->image)[i]=0;
 for(unsigned i=0;i<bytes;i+=32)purge(runner+i);
 BARRIER();
 for(unsigned i=0;i<bytes;i++)((volatile unsigned char *)c->resident)[i]=resident_begin[i];
 if(resident_fixups[0]>1023){problem="Runner table invalid";goto failed;}
 for(unsigned i=1;i<=resident_fixups[0];i++){
  unsigned off=resident_fixups[i];if(off+4>bytes||(off&3)){problem="Runner fixup invalid";goto failed;}
  uint32_t v=REG(c->resident+off);if(v<(uintptr_t)resident_begin||v>=(uintptr_t)resident_end){problem="Runner pointer bad";goto failed;}
  REG(c->resident+off)=v-(uintptr_t)resident_begin+c->resident;
 }
 uintptr_t gate=c->resident+(uintptr_t)resident_gateway-(uintptr_t)resident_begin;
 for(unsigned i=0;i<profile.patch_count;i++){
  uintptr_t dest=c->image+profile.patches[i];if(REG(dest)!=0x80010070){problem="Gate patch mismatch";goto failed;}REG(dest)=gate;
 }
 log_event(c,"GATES_PATCHED",profile.patch_count,gate);
 for(unsigned i=0;i<c->mapped_bytes;i+=32)purge(c->image+i);
 BARRIER();
 for(unsigned i=0;i<c->mapped_bytes;i+=32)invalidate(c->image+i);
 BARRIER();
 /* The selecting EXE must not become an input to the target's first screen. */
 uint16_t matrix=0;
 while(r_any_key(&matrix))r_sleep(10);
 r_clear_keys();
 int (*run)(Context *)=(int (*)(Context *))(c->resident+(uintptr_t)resident_main-(uintptr_t)resident_begin);
 int result=run(c);release(c);
 show(result?"Run needs review":"Target returned","Saved Loader.txt");int key=0;while(key!=30002)r_getkey(&key);return 1;
failed:
 log_text(c,"REJECTED=");log_text(c,problem);log_text(c,"\n");int saved=log_save(c);release(c);
 show(problem,saved?"Saved Loader.txt":"Log unavailable");{int key=0;while(key!=30002)r_getkey(&key);}return 1;
}

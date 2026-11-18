#include "loader.h"
void *memcpy(void *out,const void *in,size_t n)
{unsigned char *d=out;const unsigned char *s=in;while(n--)*d++=*s++;return out;}
void *memset(void *out,int value,size_t n)
{unsigned char *d=out;while(n--)*d++=(unsigned char)value;return out;}
typedef struct {char id[9],title[32];unsigned legacy,bytes,kind;} Item;
typedef struct {char id[8],title[16];} OldItem;
typedef struct {char magic[8];uint32_t count;OldItem item[8];} Catalog;
typedef struct {char magic[8];uint32_t version,kind,bytes,flags;char title[32];unsigned char reserved[8];} Metadata;
typedef struct {char magic[8];uint32_t version,bytes,pages,profile_hash;unsigned char sha[32];uint32_t hashes_hash,reserved;} Cache;
_Static_assert(sizeof(Metadata)==64&&sizeof(Cache)==64,"directory ABI");
static void wide(uint16_t *out,const char *p){while(*p)*out++=(unsigned char)*p++;*out=0;}
static int equal(const void *av,const void *bv,unsigned n)
{const unsigned char *a=av,*b=bv;while(n--)if(*a++!=*b++)return 0;return 1;}
static void path(uint16_t *p,const Item *item,const char *leaf,const char *suffix)
{
 char out[64]="\\\\fls0\\";unsigned n=7;
 if(!item->legacy){const char *s="FXAPPS\\";while(*s)out[n++]=*s++;}
 for(unsigned i=0;item->id[i]&&i<8;i++)out[n++]=item->id[i];
 if(!item->legacy){out[n++]='\\';suffix=leaf;}
 while(*suffix)out[n++]=*suffix++;
 out[n]=0;wide(p,out);
}
static void show(const char *a,const char *b)
{r_clear();r_print(0,0,(const unsigned char *)"FX / APPS",0);r_print(0,18,(const unsigned char *)a,0);r_print(0,32,(const unsigned char *)b,0);r_print(0,53,(const unsigned char *)"EXIT: back",0);r_display();}
static int exact(const uint16_t *p,void *out,unsigned n)
{int fd=r_open(p,1,0);if(fd<0)return 0;int got=r_size(fd)==(int)n?r_read(fd,out,n,0):-1,rc=r_close(fd);return got==(int)n&&rc>=0;}
static int valid_id(const uint16_t *s,char *out)
{
 unsigned i=0;for(;i<8&&s[i];i++){unsigned x=s[i];if(!((x>='a'&&x<='z')||(x>='A'&&x<='Z')||(x>='0'&&x<='9')||x=='_'))return 0;out[i]=(char)x;}
 out[i]=0;return i&&s[i]==0;
}
static unsigned catalog(Item *items,unsigned *overflow)
{
 uint16_t filename[64],found[256];FileInfo info;int handle=-1;unsigned count=0;*overflow=0;
 wide(filename,"\\\\fls0\\FXAPPS\\*");int rc=r_find_first(filename,&handle,found,&info);
 while(rc>=0){
  Item item;memset(&item,0,sizeof item);
  if(info.type==0&&valid_id(found,item.id)){
   Metadata meta;path(filename,&item,"APP.MET","");
   if(exact(filename,&meta,sizeof meta)&&equal(meta.magic,"FXAPPM01",8)&&meta.version==1&&meta.flags==0&&
      (meta.kind==1||meta.kind==2)&&meta.bytes>=516&&meta.title[0]&&!meta.title[31]){
    int printable=1;for(unsigned j=0;meta.title[j];j++)if((unsigned char)meta.title[j]<32||(unsigned char)meta.title[j]>126)printable=0;
    if(printable){memcpy(item.title,meta.title,32);item.bytes=meta.bytes;item.kind=meta.kind;if(count<32)items[count++]=item;else *overflow=1;}
   }
  }
  rc=r_find_next(handle,found,&info);
 }
 if(handle>=0)r_find_close(handle);
 if(count)return count;
 Catalog cat;wide(filename,"\\\\fls0\\Loader.idx");
 if(!exact(filename,&cat,sizeof cat)||!equal(cat.magic,"FXLDIDX1",8)||!cat.count||cat.count>8)return 0;
 for(unsigned i=0;i<cat.count;i++){
  if(!cat.item[i].id[0]||cat.item[i].id[7]||cat.item[i].title[15])return 0;
  for(unsigned j=0;j<8;j++)found[j]=(unsigned char)cat.item[i].id[j];
  if(!valid_id(found,items[i].id))return 0;
  memset(items[i].title,0,32);memcpy(items[i].title,cat.item[i].title,16);items[i].legacy=1;items[i].kind=1;items[i].bytes=0;
 }return cat.count;
}
static void rect(unsigned char *v,unsigned x,unsigned y,unsigned w,unsigned h)
{for(unsigned r=y;r<y+h&&r<64;r++)for(unsigned c=x;c<x+w&&c<128;c++)v[r*16+c/8]|=128>>(c&7);}
static void item_icon(const Item *item,unsigned y)
{
 unsigned char bits[68];uint16_t name[64];path(name,item,"ICON.BIN",".ico");unsigned char *v=r_vram();
 if(exact(name,bits,sizeof bits)){for(unsigned r=0;r<17;r++)for(unsigned c=0;c<4;c++)v[(y+r)*16+c]=bits[r*4+c];}
 else {rect(v,3,y+2,22,1);rect(v,3,y+2,1,14);rect(v,3,y+15,22,1);rect(v,24,y+2,1,14);rect(v,7,y+6,13,2);rect(v,7,y+10,9,2);}
}
static int choose(Item *selected,unsigned *fast)
{
 Item items[32];unsigned overflow=0,count=catalog(items,&overflow);if(!count)return -1;
 unsigned current=0;
 for(;;){
  r_clear();r_print(0,0,(const unsigned char *)"FX / APPS",0);r_print(76,0,(const unsigned char *)(*fast?"FAST":"FULL"),0);
  for(unsigned i=0;i<2;i++){unsigned k=(current/2)*2+i,y=12+20*i;if(k>=count)break;char title[15];unsigned j=0;for(;j<14&&items[k].title[j];j++)title[j]=items[k].title[j];title[j]=0;
   item_icon(&items[k],y);r_print(34,y,(const unsigned char *)title,k==current);
   r_print(34,y+9,(const unsigned char *)(items[k].kind==2||items[k].bytes>0x200000?"EXT loader req.":"Flash mapping"),0);
  }
  r_print(0,53,(const unsigned char *)(overflow?"32 max F1/F2 EXE EXIT":"F1/F2 mode EXE EXIT"),0);r_display();
  int key=0;r_getkey(&key);if(key==30002)return 0;
  if(key==30018)current=(current+count-1)%count;
  if(key==30023)current=(current+1)%count;
  if(key==30009)*fast=0;
  if(key==30010){show("Fast: trusts cache","May miss BIN changes");r_print(0,43,(const unsigned char *)"EXE: accept",0);r_display();int confirm=0;r_getkey(&confirm);if(confirm==30004)*fast=1;}
  if(key==30004){if(items[current].kind==2||items[current].bytes>0x200000){show("Over 2 MiB window","Use EXT loader");int back=0;r_getkey(&back);continue;}*selected=items[current];return 1;}
 }
}
static void finalize(Context *c){r_quit(0);r_free(c);}
typedef struct {
 unsigned candidates, conflicts;
 uintptr_t first, last;
} RamSearch;

/* Ask the OS for owned blocks only. Keep rejected allocations occupied so
 * the allocator can offer another address. No guest code runs during search. */
static Context *allocate_resident(unsigned bytes,const Profile *profile,RamSearch *stats,const char **why)
{
 typedef struct Held { struct Held *next; } Held;
 Held *held=NULL;
 Context *selected=NULL;
 for(;;){
  void *block=r_malloc(bytes);
  if(!block){
   *why=stats->conflicts?"No fitting OS block":"Not enough RAM";
   break;
  }
  uintptr_t begin=(uintptr_t)block,end=begin+bytes;
  if(!stats->candidates)stats->first=begin;
  stats->last=begin;
  stats->candidates++;
  if(begin<0x80000000u||end<=begin||end>0xa0000000u){
   r_free(block);*why="Unsupported heap";break;
  }
  uintptr_t skip_to=begin;
  for(unsigned i=0;i<profile->forbid_count;i++){
   uintptr_t low=profile->forbidden[i][0],high=profile->forbidden[i][1];
   if(begin<high&&low<end&&high>skip_to)skip_to=high;
  }
  if(skip_to==begin){selected=block;break;}
  stats->conflicts++;
  if(skip_to<end){
   /* Leave the usable suffix available. A full-size placeholder here could
    * consume the start of the only viable block near a range boundary. */
   unsigned prefix=(unsigned)(skip_to-begin);
   if(prefix<sizeof(Held))prefix=sizeof(Held);
   r_free(block);
   block=r_malloc(prefix);
   if(!block){*why="RAM search interrupted";break;}
  }
  Held *reservation=block;
  reservation->next=held;
  held=reservation;
 }
 while(held){
  Held *next=held->next;
  r_free(held);
  held=next;
 }
 return selected;
}

static void log_hex(char *buffer,unsigned *used,const char *label,uint32_t value)
{
 while(*label)buffer[(*used)++]=*label++;
 for(int shift=28;shift>=0;shift-=4){
  unsigned digit=(value>>shift)&15u;
  buffer[(*used)++]=(char)(digit<10?'0'+digit:'A'+digit-10);
 }
 buffer[(*used)++]='\n';
}

static void failure(const uint16_t *p,const char *why,unsigned required,const RamSearch *stats)
{
 char b[512];int fd=r_open(p,1,0);if(fd<0)return;
 int ok=r_size(fd)==LOG_BYTES&&r_read(fd,b,8,0)==8&&equal(b,"FXFLASH1",8);if(r_close(fd)<0)ok=0;if(!ok)return;
 for(unsigned i=0;i<sizeof b;i++)b[i]=' ';
 const char *s="FXFLASH1\nSTART_FAILED=";unsigned n=0;while(*s)b[n++]=*s++;while(*why&&n<128)b[n++]=*why++;
 b[n++]='\n';
 log_hex(b,&n,"REQUIRED_BYTES=",required);
 log_hex(b,&n,"RAM_CANDIDATES=",stats->candidates);
 log_hex(b,&n,"RAM_CONFLICTS=",stats->conflicts);
 log_hex(b,&n,"RAM_FIRST=",stats->first);
 log_hex(b,&n,"RAM_LAST=",stats->last);
 s="\nRUN_END\n";while(*s)b[n++]=*s++;
 fd=r_open(p,2,0);if(fd>=0){r_write(fd,b,sizeof b);r_close(fd);}
}
static __attribute__((noinline)) int verify_image(Context *c,int fd)
{
 Sha256 hash;sha_init(&hash);unsigned char buffer[4096],digest[32];int ok=1;
 for(unsigned off=0;off<c->image_bytes;off+=4096){
  unsigned n=c->image_bytes-off;if(n>4096)n=4096;
  if(r_read(fd,buffer,n,off)!=(int)n){ok=0;break;}
  sha_update(&hash,buffer,n);uint32_t h=2166136261u;
  for(unsigned j=0;j<n;j++)h=(h^buffer[j])*16777619u;
  c->hashes[off/4096]=h;
 }
 int rc=r_close(fd);sha_final(&hash,digest);return ok&&rc>=0&&equal(digest,c->profile.sha256,32);
}
static uint32_t fnv(const void *data,unsigned n)
{const unsigned char *p=data;uint32_t h=2166136261u;while(n--)h=(h^*p++)*16777619u;return h;}
static int load_cache(Context *c,const uint16_t *name)
{
 Cache h;int fd=r_open(name,1,0);if(fd<0)return 0;
 int ok=r_size(fd)==4096&&r_read(fd,&h,sizeof h,0)==sizeof h;
 if(ok)ok=equal(h.magic,"FXFSC001",8)&&h.version==1&&h.bytes==c->image_bytes&&h.pages==c->image_pages&&h.reserved==0&&
  h.profile_hash==fnv(&c->profile,sizeof c->profile)&&equal(h.sha,c->profile.sha256,32);
 if(ok)ok=r_read(fd,c->hashes,c->image_pages*4,sizeof h)==(int)c->image_pages*4&&h.hashes_hash==fnv(c->hashes,c->image_pages*4);
 if(r_close(fd)<0)ok=0;
 return ok;
}
/* The cache is optional. Its checksum and profile binding detect torn/stale
 * writes, not malicious edits. Commit the header only after all page hashes. */
static void save_cache(Context *c,const uint16_t *name)
{
 int fd=r_open(name,1,0);if(fd<0)return;int ok=r_size(fd)==4096;if(r_close(fd)<0)ok=0;if(!ok)return;
 Cache h;memset(&h,0,sizeof h);memcpy(h.magic,"FXFSC001",8);h.version=1;h.bytes=c->image_bytes;h.pages=c->image_pages;
 h.profile_hash=fnv(&c->profile,sizeof c->profile);memcpy(h.sha,c->profile.sha256,32);h.hashes_hash=fnv(c->hashes,c->image_pages*4);
 fd=r_open(name,2,0);if(fd<0)return;
 ok=r_seek(fd,sizeof h)>=0&&r_write(fd,c->hashes,c->image_pages*4)==(int)c->image_pages*4;
 if(ok&&r_seek(fd,0)>=0)r_write(fd,&h,sizeof h);
 r_close(fd);
}
/* Release the browser and verification workspace before the guest starts. */
static __attribute__((noinline)) Context *prepare_launch(unsigned *legacy)
{
 Item item;unsigned fast=0;int choice=choose(&item,&fast);if(!choice)return NULL;
 uint16_t log_path[64];wide(log_path,"\\\\fls0\\FlashLd.txt");
 RamSearch search={0};Context *c=0;unsigned total=0;const char *why="Bad/missing catalog";
 if(choice<0)goto fail;
 if(!item.legacy)path(log_path,&item,"RUN.LOG","");
 unsigned started=(unsigned)r_ticks();
 show("Checking BIN","Please wait");
 uint32_t sp;__asm__ volatile("mov r15,%0":"=r"(sp));
 if(sp<0x8804c000u||sp>=0x88051000u){why="Unsupported stack";goto fail;}
 Profile profile;uint16_t filename[64];path(filename,&item,"APP.FPF",".fpf");
 if(!exact(filename,&profile,sizeof profile)){why="Missing/bad profile";goto fail;}
 if(!equal(profile.magic,"FXLDF001",8)||profile.version!=1||profile.bytes<516||profile.bytes>0x200000||
    profile.entry<BASE+512||profile.entry>=BASE+profile.bytes||(profile.entry&1)||profile.flags!=2||
    !profile.patch_count||profile.patch_count>MAX_PATCHES||profile.forbid_count>8){why="Invalid profile";goto fail;}
 if(!item.legacy&&item.bytes!=profile.bytes){why="MET/profile size";goto fail;}
 unsigned pages=(profile.bytes+4095)/4096,colors[2]={0,0},previous=512;
 for(unsigned i=0;i<profile.patch_count;i++){
  unsigned off=profile.patches[i],page=off/4096;
  if(off<512||(off&3)||off>profile.bytes-4||(i&&profile.patches[i-1]>=off)){why="Invalid patch";goto fail;}
  if(previous!=page){colors[page&1]++;previous=page;}
 }
 for(unsigned i=0;i<profile.forbid_count;i++)if(profile.forbidden[i][0]>=profile.forbidden[i][1]||
    (profile.forbidden[i][0]&0xe0000000u)!=0x80000000u||(profile.forbidden[i][1]&0xe0000000u)!=0x80000000u){why="Invalid RAM range";goto fail;}
 /* A 4 KiB-aligned base can have either cache color. Reserve the worst
  * slot span, then select slot parity from the actual allocated address.
  * Balanced colors save 4 KiB versus forcing an 8 KiB-aligned base. */
 unsigned span=2*(colors[0]>colors[1]?colors[0]:colors[1])*4096,bytes=resident_end-resident_begin;
 total=(sizeof(Context)+pages*8+31+bytes+4095+span+31)&~31u;
 c=allocate_resident(total,&profile,&search,&why);if(!c)goto fail;
 uintptr_t end=(uintptr_t)c+total;
 memset(c,0,sizeof *c);c->finalize=finalize;c->allocation_bytes=total;c->runner_bytes=bytes;c->profile=profile;
 c->ram_candidates=search.candidates;c->started_tick=started;
 c->image_bytes=profile.bytes;c->image_pages=pages;c->shadow_span=span;c->shadow_count=colors[0]+colors[1];
 c->pages=(uint32_t *)(c+1);c->hashes=c->pages+pages;memset(c->pages,0,pages*8);memset(c->shadow_slot,255,512);
 c->ram_word=REG(0x08100000);
 memcpy(c->log_path,log_path,sizeof log_path);wide(c->self_path,"\\\\fls0\\FlashLd.g1a");path(c->bin_path,&item,"IMAGE.BIN",".bin");
 path(filename,&item,"VERIFY.CCH",".cch");
 int fd=r_open(c->bin_path,1,0);if(fd<0){why="Missing BIN";goto fail;}
 if(r_size(fd)!=(int)c->image_bytes){r_close(fd);why="Wrong BIN size";goto fail;}
 unsigned vt=(unsigned)r_ticks();
 if(fast&&load_cache(c,filename)){c->fast=1;show("Fast: cached check","Mapping pages");if(r_close(fd)<0){why="BIN close failed";goto fail;}}
 else {if(fast)show("Full check needed","Building fast cache");if(!verify_image(c,fd)){why="BIN hash mismatch";goto fail;}save_cache(c,filename);}
 c->verify_ticks=(unsigned)r_ticks()-vt;
 uintptr_t runner=((uintptr_t)(c->hashes+pages)+31)&~31u;c->resident=runner|0x20000000u;c->shadow=(runner+bytes+4095)&~4095u;
 colors[0]=(c->shadow>>12)&1;colors[1]=colors[0]^1;
 for(unsigned i=0;i<profile.patch_count;i++){unsigned page=profile.patches[i]/4096;if(c->shadow_slot[page]==255){c->shadow_slot[page]=colors[page&1];colors[page&1]+=2;}}
 if(c->shadow+span>end){why="Allocation bounds";goto fail;}
 for(unsigned i=0;i<bytes;i+=32)purge(runner+i);
 BARRIER();for(unsigned i=0;i<bytes;i++)BYTE(c->resident+i)=resident_begin[i];
 if(resident_fixups[0]>1023){why="Fixup table";goto fail;}
 for(unsigned i=1;i<=resident_fixups[0];i++){
  unsigned off=resident_fixups[i];if(off+4>bytes||(off&3)){why="Fixup offset";goto fail;}
  uint32_t v=REG(c->resident+off);if(v<(uintptr_t)resident_begin||v>=(uintptr_t)resident_end){why="Fixup value";goto fail;}
  REG(c->resident+off)=v-(uintptr_t)resident_begin+c->resident;
 }
 BARRIER();unsigned rt=(unsigned)r_ticks();uint16_t matrix=0;while(r_any_key(&matrix))r_sleep(10);r_clear_keys();c->release_ticks=(unsigned)r_ticks()-rt;
 *legacy=item.legacy;
 return c;
fail:
 if(c)r_free(c);
 failure(log_path,why,total,&search);show(why,choice>0&&!item.legacy?"See RUN.LOG":"See FlashLd.txt");{int key=0;while(key!=30002)r_getkey(&key);}return NULL;
}

int main(void)
{
 unsigned legacy=0;
 Context *c=prepare_launch(&legacy);
 if(!c)return 1;
 int (*run)(Context *)=(int(*)(Context *))(c->resident+(uintptr_t)resident_main-(uintptr_t)resident_begin);
 int result=run(c);
 r_quit(0);r_free(c);
 if(!result)return 1;
 show("Stopped: see log",legacy?"Saved FlashLd.txt":"Saved RUN.LOG");
 int key=0;
 while(key!=30002)r_getkey(&key);
 return 1;
}

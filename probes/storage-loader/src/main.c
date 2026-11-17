#include "loader.h"
void *memcpy(void *out,const void *in,size_t n)
{unsigned char *d=out;const unsigned char *s=in;while(n--)*d++=*s++;return out;}
void *memset(void *out,int value,size_t n)
{unsigned char *d=out;while(n--)*d++=(unsigned char)value;return out;}
typedef struct {char id[8],title[16];} Item;
typedef struct {char magic[8];uint32_t count;Item item[8];} Catalog;
static void wide(uint16_t *out,const char *p){while(*p)*out++=(unsigned char)*p++;*out=0;}
static int equal(const void *av,const void *bv,unsigned n)
{const unsigned char *a=av,*b=bv;while(n--)if(*a++!=*b++)return 0;return 1;}
static void path(uint16_t *p,const char *id,const char *suffix)
{char out[32]="\\\\fls0\\";unsigned n=7;for(unsigned i=0;id[i]&&i<8;i++)out[n++]=id[i];while(*suffix)out[n++]=*suffix++;out[n]=0;wide(p,out);}
static void show(const char *a,const char *b)
{r_clear();r_print(0,0,(const unsigned char *)"Flash Loader 0.1",0);r_print(0,18,(const unsigned char *)a,0);r_print(0,32,(const unsigned char *)b,0);r_print(0,53,(const unsigned char *)"EXIT: menu",0);r_display();}
static int exact(const uint16_t *p,void *out,unsigned n)
{int fd=r_open(p,1,0);if(fd<0)return 0;int got=r_size(fd)==(int)n?r_read(fd,out,n,0):-1,rc=r_close(fd);return got==(int)n&&rc>=0;}
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
  r_clear();r_print(0,0,(const unsigned char *)"Flash Loader 0.1",0);
  for(unsigned i=0;i<4;i++){unsigned k=(current/4)*4+i;if(k>=cat.count)break;r_print(0,12+10*i,(const unsigned char *)(k==current?">":" "),0);r_print(8,12+10*i,(const unsigned char *)cat.item[k].title,0);}
  r_print(0,54,(const unsigned char *)"UP/DN EXE  EXIT",0);r_display();
  int key=0;r_getkey(&key);if(key==30002)return 0;
  if(key==30018)current=(current+cat.count-1)%cat.count;
  if(key==30023)current=(current+1)%cat.count;
  if(key==30004){*selected=cat.item[current];return 1;}
 }
}
static void finalize(Context *c){r_quit(0);r_free(c);}
static void failure(const char *why,unsigned required)
{
 uint16_t p[32];wide(p,"\\\\fls0\\FlashLd.txt");char b[512];int fd=r_open(p,1,0);if(fd<0)return;
 int ok=r_size(fd)==LOG_BYTES&&r_read(fd,b,8,0)==8&&equal(b,"FXFLASH1",8);if(r_close(fd)<0)ok=0;if(!ok)return;
 for(unsigned i=0;i<sizeof b;i++)b[i]=' ';
 const char *s="FXFLASH1\nSTART_FAILED=";unsigned n=0;while(*s)b[n++]=*s++;while(*why&&n<450)b[n++]=*why++;
 s="\nREQUIRED_BYTES=";while(*s)b[n++]=*s++;
 for(int i=7;i>=0;i--){unsigned v=(required>>(i*4))&15;b[n++]=(char)(v<10?'0'+v:'A'+v-10);}b[n]='\n';
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
int main(void)
{
 Item item;int choice=choose(&item);if(!choice)return 1;
 Context *c=0;unsigned total=0;const char *why="Bad/missing catalog";
 if(choice<0)goto fail;
 show("Checking BIN","Please wait");
 uint32_t sp;__asm__ volatile("mov r15,%0":"=r"(sp));
 if(sp<0x8804c000u||sp>=0x88051000u){why="Unsupported stack";goto fail;}
 Profile profile;uint16_t filename[32];path(filename,item.id,".fpf");
 if(!exact(filename,&profile,sizeof profile)){why="Missing/bad profile";goto fail;}
 if(!equal(profile.magic,"FXLDF001",8)||profile.version!=1||profile.bytes<516||profile.bytes>0x200000||
    profile.entry<BASE+512||profile.entry>=BASE+profile.bytes||(profile.entry&1)||profile.flags!=2||
    !profile.patch_count||profile.patch_count>MAX_PATCHES||profile.forbid_count>8){why="Invalid profile";goto fail;}
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
 c=r_malloc(total);if(!c){why="Not enough RAM";goto fail;}
 uintptr_t start=(uintptr_t)c,end=start+total;
 if((start&0xe0000000u)!=0x80000000u||end<start){why="Unsupported heap";goto fail;}
 for(unsigned i=0;i<profile.forbid_count;i++)if(start<profile.forbidden[i][1]&&end>profile.forbidden[i][0]){why="Target RAM conflict";goto fail;}
 memset(c,0,sizeof *c);c->finalize=finalize;c->allocation_bytes=total;c->runner_bytes=bytes;c->profile=profile;
 c->image_bytes=profile.bytes;c->image_pages=pages;c->shadow_span=span;c->shadow_count=colors[0]+colors[1];
 c->pages=(uint32_t *)(c+1);c->hashes=c->pages+pages;memset(c->pages,0,pages*8);memset(c->shadow_slot,255,512);
 c->ram_word=REG(0x08100000);
 wide(c->log_path,"\\\\fls0\\FlashLd.txt");wide(c->self_path,"\\\\fls0\\FlashLd.g1a");path(c->bin_path,item.id,".bin");
 int fd=r_open(c->bin_path,1,0);if(fd<0){why="Missing BIN";goto fail;}
 if(r_size(fd)!=(int)c->image_bytes){r_close(fd);why="Wrong BIN size";goto fail;}
 if(!verify_image(c,fd)){why="BIN hash mismatch";goto fail;}
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
 BARRIER();uint16_t matrix=0;while(r_any_key(&matrix))r_sleep(10);r_clear_keys();
 int (*run)(Context *)=(int(*)(Context *))(c->resident+(uintptr_t)resident_main-(uintptr_t)resident_begin);
 int result=run(c);r_quit(0);r_free(c);c=0;
 show(result?"Stopped: see log":"Target returned","Saved FlashLd.txt");
 {int key=0;while(key!=30002)r_getkey(&key);}return 1;
fail:
 if(c)r_free(c);
 failure(why,total);show(why,"See FlashLd.txt");{int key=0;while(key!=30002)r_getkey(&key);}return 1;
}

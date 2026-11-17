#include "probe.h"
static void wide(uint16_t *out,const char *p){while(*p)*out++=(unsigned char)*p++;*out=0;}
int main(void)
{
 r_clear();r_print(0,0,(const unsigned char *)"698-page probe",0);r_display();
 unsigned n=resident_end-resident_begin,bytes=(sizeof(Context)+255+n+31)&~31u;
 Context *c=r_malloc(bytes);void *reserve=r_malloc(32768);
 if(!c||!reserve){
  if(c)r_free(c);
  if(reserve)r_free(reserve);
  r_print(0,16,(const unsigned char *)"Allocation failed",0);r_display();return 1;
 }
 for(unsigned i=0;i<sizeof *c;i++)((unsigned char *)c)[i]=0;
 c->resident_bytes=n;c->allocation_bytes=bytes;
 wide(c->bin_path,"\\\\fls0\\Map698.bin");wide(c->log_path,"\\\\fls0\\Map698.txt");
 uint16_t config[32];wide(config,"\\\\fls0\\Map698.cfg");char mode=0;
 int fd=r_open(config,1,0);if(fd>=0){r_read(fd,&mode,1,0);r_close(fd);}
 c->mode=mode=='O'?0:mode=='M'?1:mode=='A'?2:99;
 if(c->mode==99){r_free(reserve);r_free(c);return 1;}
 for(unsigned i=0;i<32768;i++)((volatile unsigned char *)reserve)[i]=(unsigned char)(i*13+7);
 uintptr_t runner=((uintptr_t)c+sizeof(Context)+255)&~255u,uncached=runner|0x20000000u;
 for(unsigned i=0;i<n;i+=32)purge(runner+i);
 BARRIER();
 for(unsigned i=0;i<n;i++)BYTE(uncached+i)=resident_begin[i];
 if(resident_fixups[0]>1023){r_free(reserve);r_free(c);return 1;}
 for(unsigned i=1;i<=resident_fixups[0];i++){
  uint32_t off=resident_fixups[i];if(off+4>n||(off&3)){r_free(reserve);r_free(c);return 1;}
  uint32_t v=REG(uncached+off);if(v<(uintptr_t)resident_begin||v>=(uintptr_t)resident_end){r_free(reserve);r_free(c);return 1;}
  REG(uncached+off)=v-(uintptr_t)resident_begin+uncached;
 }BARRIER();
 int (*run)(Context *)=(int(*)(Context *))(uncached+(uintptr_t)resident_main-(uintptr_t)resident_begin);
 int result=run(c);
 for(unsigned i=0;i<32768;i++)if(((volatile unsigned char *)reserve)[i]!=(unsigned char)(i*13+7))result=90;
 r_clear();r_print(0,0,(const unsigned char *)"698-page probe",0);
 r_print(0,16,(const unsigned char *)(result?"FAILED: read log":"PASS 698 / CAS32"),0);
 r_print(0,32,(const unsigned char *)"No CAS executed",0);
 r_print(0,48,(const unsigned char *)"EXIT: return",0);r_display();
 int key=0;while(key!=30002&&key!=30010)r_getkey(&key);
 r_free(reserve);r_free(c);return 1;
}

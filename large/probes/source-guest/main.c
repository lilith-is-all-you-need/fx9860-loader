#include <fxlarge/runtime.h>
#include <fxlarge/profile.h>
/* The loader world remains active: no target VBR/driver ownership here.
   No C runtime globals are assumed initialized before the explicit bind. */
int main(int isappli,int opt,FxLargeApi *api)
{
 (void)isappli;(void)opt;
 if(!fxlarge_bind(api))return 1;
 unsigned bytes=*(volatile const uint32_t *)(FXLARGE_BASE+24)+512u;
 unsigned pages=(bytes+4095u)/4096u;
 for(unsigned p=0;p<pages;p++){
  uint32_t word=*(volatile const uint32_t *)(FXLARGE_BASE+p*4096u);
  if(word!=(p?0xfaca0000u|p:0x46584c41u)){
   fxlarge_stage(6,2,p);fxlarge_unbind();return 2;
  }
 }
 fxlarge_stage(6,1,0xd0000000u|pages);
 return fxlarge_unbind()?0:3;
}

#ifndef FXLARGE_CATALOG_H
#define FXLARGE_CATALOG_H
/* OS-world only. Close search handles before entering the resident mapper. */
typedef struct {uint16_t index,type;uint32_t size,data_size,property,address;} FxFileInfo;
int r_find_first(const uint16_t *,int *,uint16_t *,FxFileInfo *);
int r_find_next(int,uint16_t *,FxFileInfo *);int r_find_close(int);
typedef struct {char id[9],title[32];} FxAppItem;
static void fx_path(uint16_t *out,const char *id,const char *leaf)
{
 const char *prefix="\\\\fls0\\";while(*prefix)*out++=(unsigned char)*prefix++;
 if(id[0]){prefix="FXAPPS\\";while(*prefix)*out++=(unsigned char)*prefix++;
  while(*id)*out++=(unsigned char)*id++;
  *out++='\\';}
 while(*leaf)*out++=(unsigned char)*leaf++;
 *out=0;
}
static int fx_exact(const uint16_t *path,void *buffer,unsigned n)
{int fd=r_open(path,1,0);if(fd<0)return 0;int got=r_size(fd)==(int)n?r_read(fd,buffer,n,0):-1;int rc=r_close(fd);return got==(int)n&&rc>=0;}
static int fx_id(const uint16_t *in,char *out)
{
 unsigned n=0;for(;n<8&&in[n];n++){unsigned c=in[n];
  if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'))return 0;
  out[n]=(char)c;}
 out[n]=0;return n&&in[n]==0;
}
/* Returns 1 selected, 0 user cancelled, -1 no matching package. */
static int fx_choose(FxAppItem *out,const char *profile_leaf,const char *caption,unsigned expected_kind)
{
 FxAppItem items[16];unsigned count=0,overflow=0;uint16_t path[64],found[256];
 FxFileInfo info;int handle=-1;fx_path(path,"","FXAPPS\\*");
 int rc=r_find_first(path,&handle,found,&info);
 while(rc>=0){
  FxAppItem item={{0},{0}};
  if(info.type==0&&fx_id(found,item.id)){
   fx_path(path,item.id,profile_leaf);int fd=r_open(path,1,0);
   if(fd>=0){int valid=r_size(fd)>0;if(r_close(fd)<0)valid=0;
    if(valid){for(unsigned i=0;i<9;i++)item.title[i]=item.id[i];
     unsigned char meta[64];fx_path(path,item.id,"APP.MET");
     if(fx_exact(path,meta,64)&&!meta[55]){
      unsigned i=0;int ok=1;for(;i<8;i++)if(meta[i]!=(unsigned char)"FXAPPM01"[i])ok=0;
      if(meta[8]||meta[9]||meta[10]||meta[11]!=1)ok=0;
      if(meta[12]||meta[13]||meta[14]||meta[15]!=expected_kind)valid=0;
      for(i=24;i<55&&meta[i];i++)if(meta[i]<32||meta[i]>126)ok=0;
      if(ok&&meta[24])for(i=0;i<32;i++)item.title[i]=(char)meta[24+i];
     }
     if(valid){if(count<16)items[count++]=item;else overflow=1;}
    }
   }
  }
  rc=r_find_next(handle,found,&info);
 }
 if(handle>=0&&r_find_close(handle)<0)return -1;
 if(!count)return -1;
 unsigned current=0;
 for(;;){
  r_clear();r_print(0,0,(const unsigned char *)caption,0);
  for(unsigned row=0;row<3;row++){
   unsigned i=(current/3)*3+row;if(i>=count)break;
   char title[21];unsigned n=0;while(n<20&&items[i].title[n]){title[n]=items[i].title[n];n++;}title[n]=0;
   r_print(0,14+row*12,(const unsigned char *)title,i==current);
  }
  r_print(0,53,(const unsigned char *)(overflow?"16 max EXE / EXIT":"UP/DOWN EXE / EXIT"),0);r_display();
  int key=0;r_getkey(&key);if(key==30002)return 0;
  if(key==30018)current=current?current-1:count-1;
  if(key==30023)current=current+1==count?0:current+1;
  if(key==30004){*out=items[current];return 1;}
 }
}
#endif

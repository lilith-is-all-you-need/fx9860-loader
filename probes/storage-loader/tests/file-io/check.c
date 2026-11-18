#include <stdint.h>

extern int fx_open(const uint16_t *,int,int),fx_close(int),fx_seek(int,int);
extern int fx_size(int),fx_read(int,void *,int,int),fx_write(int,const void *,int);
extern int wait_key(int *);
static const uint16_t path[]={'\\','\\','f','l','s','0','\\','I','O','.','D','A','T',0};

/* The benchmark samples this symbol after each section without modifying the guest. */
__attribute__((noinline,noclone)) void io_phase(unsigned section)
{
    __asm__ volatile(""::"r"(section):"memory");
}

int main(void)
{
    uint32_t word=0;
    int key=0,fd=fx_open(path,2,0);
    if(fd<0)return 1;
    io_phase(0);
    for(int i=0;i<16;i++)if(fx_size(fd)!=256)return 2;
    io_phase(1);
    for(int i=0;i<16;i++)if(fx_seek(fd,i*4)<0)return 3;
    io_phase(2);
    for(int i=0;i<16;i++)if(fx_read(fd,&word,4,i*4)!=4||word!=0)return 4;
    io_phase(3);
    if(fx_seek(fd,0)<0)return 5;
    for(int i=0;i<16;i++){
        word=0x130000u+i;
        if(fx_write(fd,&word,4)!=4)return 6;
    }
    io_phase(4);
    for(int i=0;i<16;i++)
        if(fx_read(fd,&word,4,i*4)!=4||word!=0x130000u+(unsigned)i)return 7;
    if(fx_close(fd)<0)return 8;
    io_phase(5);
    do{wait_key(&key);}while(key!=30002);
    io_phase(6);
    return 42;
}

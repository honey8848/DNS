@echo off
REM 编译DNS服务器程序
REM 使用gcc编译器
REM 链接Windows Socket库(ws2_32)
REM 输出文件名为dns.exe

gcc main.c dns_server.c dns_resolver.c dns_message.c -o dns.exe -lws2_32 
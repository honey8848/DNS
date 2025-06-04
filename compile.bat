@echo off
REM 编译DNS服务器程序
REM 使用g++编译器，启用C++11标准
REM 链接Windows Socket库(ws2_32)
REM 输出文件名为dns.exe

g++ -std=c++11 main.cpp dns_server.cpp dns_resolver.cpp dns_message.cpp -o dns.exe -lws2_32 
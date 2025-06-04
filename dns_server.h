/**
 * @file dns_server.h
 * @brief DNS服务器类的头文件定义
 * @details 定义了DNS服务器的主要功能，包括初始化、启动、处理查询等功能
 */

#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <winsock2.h>
#include "dns_resolver.h"
#include <windows.h>

// DNS服务器结构体
typedef struct {
    SOCKET sockfd;           // 服务器套接字
    DNSResolver* resolver;   // DNS解析器实例
    int initialized;         // 服务器初始化状态标志
} DNSServer;

// 调试日志函数
void debug_log(const char* format, ...);

// 函数声明
DNSServer* createServer(void);
void destroyServer(DNSServer* server);
int initServer(DNSServer* server, int port);
int loadDomainFile(DNSServer* server, const char* filename);
int startServer(DNSServer* server);
void handleQuery(DNSServer* server, const char* buffer, size_t length, 
                const struct sockaddr_in* clientAddr);

#endif // DNS_SERVER_H 
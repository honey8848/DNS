/**
 * @file dns_resolver.h
 * @brief DNS解析器类的头文件定义
 * @details 定义了DNS解析器的主要功能，包括本地解析、外部DNS查询和缓存管理
 */

#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <winsock2.h>

// 域名解析器结构体
typedef struct {
    char** domains;     // 域名数组
    char** ips;         // IP地址数组
    size_t count;       // 域名-IP对的数量
    size_t capacity;    // 数组容量
    CRITICAL_SECTION cs; // 临界区
} DNSResolver;

// 函数声明
DNSResolver* createResolver(void);
void destroyResolver(DNSResolver* resolver);
int loadDomainMap(DNSResolver* resolver, const char* filename);
char* resolveLocally(DNSResolver* resolver, const char* domain, int* isBlocked);
char* queryExternalDNS(const char* domain);
void cacheExternalResult(DNSResolver* resolver, const char* domain, const char* ip);

#endif // DNS_RESOLVER_H 
#include "dns_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_CAPACITY 100

DNSResolver* createResolver(void) {
    DNSResolver* resolver = (DNSResolver*)malloc(sizeof(DNSResolver));
    if (!resolver) return NULL;

    resolver->domains = (char**)malloc(INITIAL_CAPACITY * sizeof(char*));
    resolver->ips = (char**)malloc(INITIAL_CAPACITY * sizeof(char*));
    if (!resolver->domains || !resolver->ips) {
        free(resolver->domains);
        free(resolver->ips);
        free(resolver);
        return NULL;
    }

    resolver->count = 0;
    resolver->capacity = INITIAL_CAPACITY;
    InitializeCriticalSection(&resolver->cs);
    return resolver;
}

void destroyResolver(DNSResolver* resolver) {
    if (!resolver) return;

    for (size_t i = 0; i < resolver->count; i++) {
        free(resolver->domains[i]);
        free(resolver->ips[i]);
    }
    free(resolver->domains);
    free(resolver->ips);
    DeleteCriticalSection(&resolver->cs);
    free(resolver);
}

int loadDomainMap(DNSResolver* resolver, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return 0;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char* ip = strtok(line, " \t\n");
        char* domain = strtok(NULL, " \t\n");
        if (ip && domain) {
            // 检查是否需要扩容
            if (resolver->count >= resolver->capacity) {
                size_t newCapacity = resolver->capacity * 2;
                char** newDomains = (char**)realloc(resolver->domains, 
                                                  newCapacity * sizeof(char*));
                char** newIps = (char**)realloc(resolver->ips, 
                                              newCapacity * sizeof(char*));
                if (!newDomains || !newIps) {
                    free(newDomains);
                    free(newIps);
                    fclose(file);
                    return 0;
                }
                resolver->domains = newDomains;
                resolver->ips = newIps;
                resolver->capacity = newCapacity;
            }

            // 存储域名和IP
            resolver->domains[resolver->count] = _strdup(domain);
            resolver->ips[resolver->count] = _strdup(ip);
            if (!resolver->domains[resolver->count] || 
                !resolver->ips[resolver->count]) {
                fclose(file);
                return 0;
            }
            resolver->count++;
        }
    }

    fclose(file);
    return 1;
}

char* resolveLocally(DNSResolver* resolver, const char* domain, int* isBlocked) {
    EnterCriticalSection(&resolver->cs);
    
    for (size_t i = 0; i < resolver->count; i++) {
        if (strcmp(resolver->domains[i], domain) == 0) {
            *isBlocked = (strcmp(resolver->ips[i], "0.0.0.0") == 0);
            char* result = _strdup(resolver->ips[i]);
            LeaveCriticalSection(&resolver->cs);
            return result;
        }
    }
    
    LeaveCriticalSection(&resolver->cs);
    *isBlocked = 0;
    return NULL;
}

char* queryExternalDNS(const char* domain) {
    struct hostent* he = gethostbyname(domain);
    if (!he || !he->h_addr_list[0]) return NULL;

    char* ipStr = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    return ipStr ? _strdup(ipStr) : NULL;
}

void cacheExternalResult(DNSResolver* resolver, const char* domain, 
                        const char* ip) {
    EnterCriticalSection(&resolver->cs);

    // 检查是否需要扩容
    if (resolver->count >= resolver->capacity) {
        size_t newCapacity = resolver->capacity * 2;
        char** newDomains = (char**)realloc(resolver->domains, 
                                          newCapacity * sizeof(char*));
        char** newIps = (char**)realloc(resolver->ips, 
                                      newCapacity * sizeof(char*));
        if (!newDomains || !newIps) {
            LeaveCriticalSection(&resolver->cs);
            return;
        }
        resolver->domains = newDomains;
        resolver->ips = newIps;
        resolver->capacity = newCapacity;
    }

    // 存储新的域名-IP对
    resolver->domains[resolver->count] = _strdup(domain);
    resolver->ips[resolver->count] = _strdup(ip);
    if (resolver->domains[resolver->count] && resolver->ips[resolver->count]) {
        resolver->count++;
    }

    LeaveCriticalSection(&resolver->cs);
} 
#include "dns_message.h"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* extractDomain(const char* buffer, size_t length) {
    if (length < sizeof(struct DNSHeader)) {
        return NULL;
    }

    char* domain = (char*)malloc(length);
    if (!domain) return NULL;
    
    size_t pos = sizeof(struct DNSHeader);
    size_t domainPos = 0;

    // 解析域名标签
    while (pos < length && buffer[pos] != 0) {
        uint8_t labelLen = buffer[pos++];
        if (pos + labelLen > length) {
            free(domain);
            return NULL;
        }

        // 添加标签内容
        memcpy(domain + domainPos, buffer + pos, labelLen);
        domainPos += labelLen;
        domain[domainPos++] = '.';
        pos += labelLen;
    }

    // 移除最后一个点号
    if (domainPos > 0) {
        domain[domainPos - 1] = '\0';
    } else {
        domain[0] = '\0';
    }

    return domain;
}

char* buildDNSResponse(uint16_t id, const char* domain, 
                      const char* ip, int isError, size_t* responseLength) {
    if (!domain || !responseLength) {
        return NULL;
    }

    // 计算响应大小
    size_t domainLen = strlen(domain);
    size_t totalSize = sizeof(struct DNSHeader) + domainLen + 2 + 4;  // 头部 + 域名 + 类型和类 + TTL等
    if (!isError) {
        totalSize += 16;  // 回答部分的大小
    }

    char* response = (char*)malloc(totalSize);
    if (!response) return NULL;

    // 设置DNS报文头部
    struct DNSHeader* header = (struct DNSHeader*)response;
    header->id = htons(id);
    header->flags = htons(0x8180);  // 标准查询响应
    header->qdcount = htons(1);
    header->ancount = htons(isError ? 0 : 1);
    header->nscount = htons(0);
    header->arcount = htons(0);

    // 构建问题部分
    size_t pos = sizeof(struct DNSHeader);
    char* domainPtr = response + pos;
    size_t start = 0;
    size_t end = 0;

    // 解析域名标签
    while (1) {
        char* dot = strchr(domain + start, '.');
        if (!dot) break;  // 没有找到点号

        end = dot - domain;
        size_t labelLen = end - start;
        if (labelLen > 63) {  // DNS标签最大长度为63字节
            free(response);
            return NULL;
        }

        response[pos++] = (char)labelLen;
        memcpy(response + pos, domain + start, labelLen);
        pos += labelLen;
        start = end + 1;
    }

    // 处理最后一个标签
    size_t lastLabelLen = strlen(domain) - start;
    if (lastLabelLen > 63) {
        free(response);
        return NULL;
    }
    response[pos++] = (char)lastLabelLen;
    memcpy(response + pos, domain + start, lastLabelLen);
    pos += lastLabelLen;
    response[pos++] = 0;  // 域名结束标记

    // 添加查询类型和类
    uint16_t qtype = htons(1);   // A记录类型
    uint16_t qclass = htons(1);  // IN类
    memcpy(response + pos, &qtype, 2);
    pos += 2;
    memcpy(response + pos, &qclass, 2);
    pos += 2;

    if (!isError) {
        // 构建回答部分
        uint16_t namePtr = htons(0xC000 | sizeof(struct DNSHeader));
        memcpy(response + pos, &namePtr, 2);
        pos += 2;
        memcpy(response + pos, &qtype, 2);
        pos += 2;
        memcpy(response + pos, &qclass, 2);
        pos += 2;

        uint32_t ttl = htonl(300);  // TTL值（5分钟）
        memcpy(response + pos, &ttl, 4);
        pos += 4;

        uint16_t rdlength = htons(4);  // IP地址长度（4字节）
        memcpy(response + pos, &rdlength, 2);
        pos += 2;

        // 转换并添加IP地址
        struct in_addr addr;
        addr.s_addr = inet_addr(ip);
        if (addr.s_addr == INADDR_NONE) {
            free(response);
            return NULL;
        }

        memcpy(response + pos, &addr.s_addr, 4);
        pos += 4;
    }

    *responseLength = pos;
    return response;
} 
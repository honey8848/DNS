#ifndef DNS_TYPES_H
#define DNS_TYPES_H

#include <cstdint>

// DNS 报文头部结构
struct DNSHeader {
    uint16_t id;       // 标识符
    uint16_t flags;    // 标志字段
    uint16_t qdcount;  // 问题数
    uint16_t ancount;  // 回答数
    uint16_t nscount;  // 授权记录数
    uint16_t arcount;  // 附加记录数
};

#endif // DNS_TYPES_H 
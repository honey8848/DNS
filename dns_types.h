/**
 * @file dns_types.h
 * @brief DNS协议相关的类型定义
 * @details 定义了DNS协议中使用的数据结构和类型
 */

#ifndef DNS_TYPES_H
#define DNS_TYPES_H

#include <cstdint>

/**
 * @struct DNSHeader
 * @brief DNS报文头部结构
 * @details 定义了DNS报文头部的格式，包含标识符、标志字段和各种记录数量
 */
struct DNSHeader {
    uint16_t id;       ///< 标识符，用于匹配请求和响应
    uint16_t flags;    ///< 标志字段，包含各种控制标志
    uint16_t qdcount;  ///< 问题数，表示查询问题的数量
    uint16_t ancount;  ///< 回答数，表示回答记录的数量
    uint16_t nscount;  ///< 授权记录数，表示授权记录的数量
    uint16_t arcount;  ///< 附加记录数，表示附加记录的数量
};

#endif // DNS_TYPES_H 
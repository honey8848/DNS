/**
 * @file dns_message.h
 * @brief DNS消息处理相关的头文件
 * @details 定义了DNS消息的解析和构建函数
 */

#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

#include <string>
#include <vector>
#include "dns_types.h"

/**
 * @brief 从DNS查询报文中提取域名
 * @param buffer DNS查询报文数据
 * @param length 报文长度
 * @return 提取出的域名
 * @details 解析DNS查询报文，提取出查询的域名
 */
std::string extractDomain(const char* buffer, size_t length);

/**
 * @brief 构建DNS响应报文
 * @param id 查询ID，用于匹配请求和响应
 * @param domain 查询的域名
 * @param ip 解析得到的IP地址
 * @param isError 是否为错误响应
 * @return 构建好的DNS响应报文
 * @details 根据查询ID、域名和IP地址构建DNS响应报文
 */
std::vector<char> buildDNSResponse(uint16_t id, const std::string& domain, const std::string& ip, bool isError);

#endif // DNS_MESSAGE_H 
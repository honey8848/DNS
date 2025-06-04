/**
 * @file dns_message.cpp
 * @brief DNS消息处理相关的实现文件
 * @details 实现了DNS消息的解析和构建功能
 */

#include "dns_message.h"
#include <winsock2.h>
#include <iostream>

using namespace std;

/**
 * @brief 从DNS查询报文中提取域名
 * @param buffer DNS查询报文数据
 * @param length 报文长度
 * @return 提取出的域名
 * @details 解析DNS查询报文，提取出查询的域名
 */
string extractDomain(const char* buffer, size_t length) {
    string domain;
    size_t pos = 12; // DNS 报文头部长度为 12 字节

    // 解析域名标签
    while (pos < length && buffer[pos] != 0) {
        uint8_t labelLen = buffer[pos++];
        if (pos + labelLen > length) break;

        // 添加标签内容
        domain.append(buffer + pos, labelLen);
        domain.append(".");
        pos += labelLen;
    }

    // 移除最后一个点号
    if (!domain.empty()) {
        domain.pop_back();
    }

    return domain;
}

/**
 * @brief 构建DNS响应报文
 * @param id 查询ID，用于匹配请求和响应
 * @param domain 查询的域名
 * @param ip 解析得到的IP地址
 * @param isError 是否为错误响应
 * @return 构建好的DNS响应报文
 * @details 根据查询ID、域名和IP地址构建DNS响应报文
 */
vector<char> buildDNSResponse(uint16_t id, const string& domain, const string& ip, bool isError) {
    vector<char> response;
    DNSHeader header;

    // 设置 DNS 报文头部
    header.id = htons(id);                    // 查询ID
    header.flags = htons(0x8180);            // 标准响应标志
    header.qdcount = htons(1);               // 一个问题
    header.ancount = htons(isError ? 0 : 1); // 一个回答（错误时无回答）
    header.nscount = htons(0);               // 无授权记录
    header.arcount = htons(0);               // 无附加记录

    // 添加报文头部
    response.insert(response.end(), (char*)&header, (char*)&header + sizeof(header));

    // 构建问题部分
    size_t domainStart = response.size();
    size_t start = 0;
    size_t end = domain.find('.');

    // 解析域名标签
    while (end != string::npos) {
        string label = domain.substr(start, end - start);
        response.push_back(label.length());  // 标签长度
        response.insert(response.end(), label.begin(), label.end());  // 标签内容
        start = end + 1;
        end = domain.find('.', start);
    }

    // 处理最后一个标签
    string lastLabel = domain.substr(start);
    response.push_back(lastLabel.length());
    response.insert(response.end(), lastLabel.begin(), lastLabel.end());
    response.push_back(0);  // 域名结束标记

    // 添加查询类型和类
    uint16_t qtype = htons(1);   // A记录类型
    uint16_t qclass = htons(1);  // IN类
    response.insert(response.end(), (char*)&qtype, (char*)&qtype + 2);
    response.insert(response.end(), (char*)&qclass, (char*)&qclass + 2);

    if (!isError) {
        // 构建回答部分
        uint16_t namePtr = htons(0xC000 | domainStart);  // 指向问题部分的指针
        response.insert(response.end(), (char*)&namePtr, (char*)&namePtr + 2);
        response.insert(response.end(), (char*)&qtype, (char*)&qtype + 2);
        response.insert(response.end(), (char*)&qclass, (char*)&qclass + 2);

        uint32_t ttl = htonl(300);  // TTL值（5分钟）
        response.insert(response.end(), (char*)&ttl, (char*)&ttl + 4);

        uint16_t rdlength = htons(4);  // IP地址长度（4字节）
        response.insert(response.end(), (char*)&rdlength, (char*)&rdlength + 2);

        // 转换并添加IP地址
        struct in_addr addr;
        addr.s_addr = inet_addr(ip.c_str());
        if (addr.s_addr == INADDR_NONE) {
            cerr << "Invalid IP address: " << ip << endl;
            return {};
        }

        response.insert(response.end(), (char*)&addr.s_addr, (char*)&addr.s_addr + 4);
    }

    return response;
} 
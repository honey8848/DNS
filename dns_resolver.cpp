/**
 * @file dns_resolver.cpp
 * @brief DNS解析器类的实现文件
 * @details 实现了DNS解析器的所有功能，包括本地解析、外部DNS查询和缓存管理
 */

#include "dns_resolver.h"
#include <fstream>
#include <winsock2.h>
#include <iostream>

using namespace std;

/**
 * @brief 构造函数
 */
DNSResolver::DNSResolver() {}

/**
 * @brief 加载域名映射文件
 * @param filename 映射文件的路径
 * @return 加载是否成功
 * @details 从文件中读取域名和IP的映射关系，格式为"IP地址 域名"
 */
bool DNSResolver::loadDomainMap(const string& filename) {
    // 打开映射文件
    ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    string line, domain, ip;
    // 使用互斥锁保护映射表的访问
    lock_guard<mutex> lock(mapMutex);
    domainIPMap.clear();

    // 逐行读取文件内容
    while (getline(file, line)) {
        size_t pos = line.find(' ');
        if (pos != string::npos) {
            ip = line.substr(0, pos);
            domain = line.substr(pos + 1);
            domainIPMap[domain] = ip;
        }
    }

    return true;
}

/**
 * @brief 本地解析域名
 * @param domain 要解析的域名
 * @param isBlocked 输出参数，指示域名是否被屏蔽
 * @return 解析得到的IP地址，如果解析失败则返回空字符串
 * @details 在本地映射表中查找域名，如果找到则返回对应的IP地址
 */
string DNSResolver::resolveLocally(const string& domain, bool& isBlocked) {
    // 使用互斥锁保护映射表的访问
    lock_guard<mutex> lock(mapMutex);
    auto it = domainIPMap.find(domain);
    if (it != domainIPMap.end()) {
        // 检查域名是否被屏蔽（IP为0.0.0.0表示被屏蔽）
        isBlocked = (it->second == "0.0.0.0");
        return it->second;
    }
    isBlocked = false;
    return "";
}

/**
 * @brief 查询外部DNS服务器
 * @param domain 要查询的域名
 * @return 查询得到的IP地址，如果查询失败则返回空字符串
 * @details 使用系统DNS解析功能查询域名的IP地址
 */
string DNSResolver::queryExternalDNS(const string& domain) {
    // 使用系统DNS解析功能
    struct hostent* he = gethostbyname(domain.c_str());
    if (he == nullptr || he->h_addr_list[0] == nullptr) {
        return "";
    }

    // 将IP地址转换为字符串格式
    char* ipStr = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    return ipStr ? string(ipStr) : "";
}

/**
 * @brief 缓存外部DNS查询结果
 * @param domain 域名
 * @param ip 对应的IP地址
 * @details 将外部DNS查询的结果保存到本地映射表中
 */
void DNSResolver::cacheExternalResult(const string& domain, const string& ip) {
    // 使用互斥锁保护映射表的访问
    lock_guard<mutex> lock(mapMutex);
    domainIPMap[domain] = ip;
} 
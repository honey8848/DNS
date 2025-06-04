/**
 * @file dns_resolver.h
 * @brief DNS解析器类的头文件定义
 * @details 定义了DNS解析器的主要功能，包括本地解析、外部DNS查询和缓存管理
 */

#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <string>
#include <map>
#include <mutex>

/**
 * @class DNSResolver
 * @brief DNS解析器类，负责域名解析和缓存管理
 */
class DNSResolver {
public:
    /**
     * @brief 构造函数
     */
    DNSResolver();

    /**
     * @brief 加载域名映射文件
     * @param filename 映射文件的路径
     * @return 加载是否成功
     */
    bool loadDomainMap(const std::string& filename);

    /**
     * @brief 本地解析域名
     * @param domain 要解析的域名
     * @param isBlocked 输出参数，指示域名是否被屏蔽
     * @return 解析得到的IP地址，如果解析失败则返回空字符串
     */
    std::string resolveLocally(const std::string& domain, bool& isBlocked);

    /**
     * @brief 查询外部DNS服务器
     * @param domain 要查询的域名
     * @return 查询得到的IP地址，如果查询失败则返回空字符串
     */
    std::string queryExternalDNS(const std::string& domain);

    /**
     * @brief 缓存外部DNS查询结果
     * @param domain 域名
     * @param ip 对应的IP地址
     */
    void cacheExternalResult(const std::string& domain, const std::string& ip);

private:
    std::map<std::string, std::string> domainIPMap;  ///< 域名到IP的映射表
    std::mutex mapMutex;                             ///< 用于保护映射表的互斥锁
};

#endif // DNS_RESOLVER_H 
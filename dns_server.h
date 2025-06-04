/**
 * @file dns_server.h
 * @brief DNS服务器类的头文件定义
 * @details 定义了DNS服务器的主要功能，包括初始化、启动、处理查询等功能
 */

#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <winsock2.h>
#include "dns_resolver.h"

/**
 * @class DNSServer
 * @brief DNS服务器类，负责处理DNS查询请求
 */
class DNSServer {
public:
    /**
     * @brief 构造函数
     */
    DNSServer();

    /**
     * @brief 析构函数
     */
    ~DNSServer();

    /**
     * @brief 初始化DNS服务器
     * @param port 服务器监听的端口号
     * @return 初始化是否成功
     */
    bool init(int port);

    /**
     * @brief 加载域名配置文件
     * @param filename 配置文件的路径
     * @return 加载是否成功
     */
    bool loadDomainFile(const std::string& filename);

    /**
     * @brief 启动DNS服务器
     * @return 启动是否成功
     */
    bool start();

    /**
     * @brief 处理DNS查询请求
     * @param buffer 接收到的DNS查询数据
     * @param length 数据长度
     * @param clientAddr 客户端地址信息
     */
    void handleQuery(const char* buffer, size_t length, const sockaddr_in& clientAddr);

private:
    SOCKET sockfd;        ///< 服务器套接字
    DNSResolver resolver; ///< DNS解析器实例
    bool initialized;     ///< 服务器初始化状态标志
};

#endif // DNS_SERVER_H 
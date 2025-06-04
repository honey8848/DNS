/**
 * @file dns_server.cpp
 * @brief DNS服务器类的实现文件
 * @details 实现了DNS服务器的所有功能，包括初始化、启动、处理查询等
 */

#include "dns_server.h"
#include "dns_message.h"
#include <iostream>
#include <thread>

using namespace std;

/**
 * @brief 构造函数
 * @details 初始化服务器套接字和状态标志
 */
DNSServer::DNSServer() : sockfd(INVALID_SOCKET), initialized(false) {}

/**
 * @brief 析构函数
 * @details 清理资源，关闭套接字和WSA
 */
DNSServer::~DNSServer() {
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    if (initialized) {
        WSACleanup();
    }
}

/**
 * @brief 初始化DNS服务器
 * @param port 服务器监听的端口号
 * @return 初始化是否成功
 * @details 初始化WSA，创建UDP套接字，绑定指定端口
 */
bool DNSServer::init(int port) {
    // 初始化WSA
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed: " << WSAGetLastError() << endl;
        return false;
    }
    initialized = true;

    // 创建UDP套接字
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == INVALID_SOCKET) {
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
        return false;
    }

    // 配置服务器地址
    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // 绑定套接字
    if (bind(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        return false;
    }

    cout << "DNS server running on port " << port << endl;
    return true;
}

/**
 * @brief 加载域名配置文件
 * @param filename 配置文件的路径
 * @return 加载是否成功
 * @details 从指定文件加载域名到IP的映射关系
 */
bool DNSServer::loadDomainFile(const string& filename) {
    if (!resolver.loadDomainMap(filename)) {
        cerr << "Failed to load domain-IP mapping file: " << filename << endl;
        return false;
    }
    cout << "Successfully loaded domain-IP mapping file" << endl;
    return true;
}

/**
 * @brief 处理DNS查询请求
 * @param buffer 接收到的DNS查询数据
 * @param length 数据长度
 * @param clientAddr 客户端地址信息
 * @details 处理DNS查询，包括本地解析、外部DNS查询和域名屏蔽
 */
void DNSServer::handleQuery(const char* buffer, size_t length, const sockaddr_in& clientAddr) {
    // 获取原始查询ID
    uint16_t originalId = ntohs(((DNSHeader*)buffer)->id);
    string domain = extractDomain(buffer, length);

    if (domain.empty()) {
        cerr << "Invalid DNS query" << endl;
        return;
    }

    cout << "Query for: " << domain << endl;

    // 尝试本地解析
    bool isBlocked = false;
    string ip = resolver.resolveLocally(domain, isBlocked);
    vector<char> response;

    if (isBlocked) {
        // 处理被屏蔽的域名
        cout << "Blocked domain: " << domain << endl;
        response = buildDNSResponse(originalId, domain, "", true);
    } else if (!ip.empty()) {
        // 本地解析成功
        cout << "Local resolution: " << domain << " -> " << ip << endl;
        response = buildDNSResponse(originalId, domain, ip, false);
    } else {
        // 尝试外部DNS解析
        cout << "Relaying query for: " << domain << endl;
        ip = resolver.queryExternalDNS(domain);

        if (!ip.empty()) {
            cout << "External resolution: " << domain << " -> " << ip << endl;
            response = buildDNSResponse(originalId, domain, ip, false);
            resolver.cacheExternalResult(domain, ip);
        } else {
            cout << "Domain not found: " << domain << endl;
            response = buildDNSResponse(originalId, domain, "", true);
        }
    }

    // 发送响应给客户端
    sendto(sockfd, response.data(), (int)response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
}

/**
 * @brief 启动DNS服务器
 * @return 启动是否成功
 * @details 启动服务器主循环，接收并处理DNS查询请求
 */
bool DNSServer::start() {
    while (true) {
        char buffer[1024];
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);

        // 接收DNS查询请求
        int recvLen = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&clientAddr, &clientLen);
        if (recvLen == SOCKET_ERROR) {
            cerr << "recvfrom failed: " << WSAGetLastError() << endl;
            continue;
        }

        // 创建新线程处理查询
        thread(&DNSServer::handleQuery, this, buffer, recvLen, clientAddr).detach();
    }
    return true;
} 
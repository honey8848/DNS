/**
 * @file main.cpp
 * @brief DNS服务器的主程序入口
 * @details 实现了DNS服务器的启动和初始化过程
 */

#include "dns_server.h"
#include <iostream>

using namespace std;

/**
 * @brief 主函数
 * @param argc 命令行参数数量
 * @param argv 命令行参数数组
 * @return 程序退出码
 * @details 解析命令行参数，初始化并启动DNS服务器
 */
int main(int argc, char* argv[]) {
    // 检查命令行参数
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <port> <domain-ip-file>" << endl;
        return 0;
    }

    // 解析命令行参数
    int port = atoi(argv[1]);         // 服务器端口号
    string domainFile = argv[2];      // 域名-IP映射文件路径

    // 创建并初始化DNS服务器
    DNSServer server;
    if (!server.init(port)) {
        cerr << "Failed to initialize DNS server" << endl;
        return 1;
    }

    // 加载域名-IP映射文件
    if (!server.loadDomainFile(domainFile)) {
        cerr << "Failed to load domain file" << endl;
        return 1;
    }

    // 启动DNS服务器
    server.start();
    return 0;
} 
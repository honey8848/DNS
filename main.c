#include "dns_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[]) {
    // 设置控制台编码为UTF-8
    SetConsoleOutputCP(65001);
    
    // 检查命令行参数
    if (argc != 3) {
        fprintf(stderr, "用法: %s <端口号> <域名映射文件>\n", argv[0]);
        fprintf(stderr, "示例: %s 5353 dnsrelay.txt\n", argv[0]);
        return 1;
    }

    // 解析命令行参数
    int port = atoi(argv[1]);
    const char* domainFile = argv[2];

    // 检查端口号是否有效
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "错误: 无效的端口号 %d\n", port);
        return 1;
    }

    // 检查文件是否存在
    FILE* testFile = fopen(domainFile, "r");
    if (!testFile) {
        fprintf(stderr, "错误: 无法打开文件 %s\n", domainFile);
        return 1;
    }
    fclose(testFile);

    printf("正在启动DNS服务器...\n");
    printf("端口: %d\n", port);
    printf("域名文件: %s\n", domainFile);

    // 创建并初始化DNS服务器
    DNSServer* server = createServer();
    if (!server) {
        fprintf(stderr, "错误: 创建DNS服务器失败\n");
        return 1;
    }

    printf("正在初始化服务器...\n");
    if (!initServer(server, port)) {
        fprintf(stderr, "错误: 初始化DNS服务器失败\n");
        destroyServer(server);
        return 1;
    }

    // 加载域名-IP映射文件
    printf("正在加载域名映射文件...\n");
    if (!loadDomainFile(server, domainFile)) {
        fprintf(stderr, "错误: 加载域名文件失败\n");
        destroyServer(server);
        return 1;
    }

    printf("DNS服务器启动成功！\n");
    printf("按Ctrl+C停止服务器\n");

    // 启动DNS服务器
    startServer(server);

    // 清理资源
    destroyServer(server);
    return 0;
}
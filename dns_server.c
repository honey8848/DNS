#include "dns_server.h"
#include "dns_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <string.h>
#include <time.h>

// 优化日志函数，支持时间戳、线程ID、日志级别、16进制数据
void debug_log_hex(const char* prefix, const void* data, int len) {
    FILE* log_file = fopen("dns_debug.log", "a");
    if (!log_file) return;
    // 时间戳
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d][TID:%lu][HEX] %s: ",
        t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
        (unsigned long)GetCurrentThreadId(), prefix);
    for (int i = 0; i < len; ++i) {
        fprintf(log_file, "%02X ", ((unsigned char*)data)[i]);
    }
    fprintf(log_file, "\n");
    fclose(log_file);
}

void debug_log(const char* format, ...) {
    FILE* log_file = fopen("dns_debug.log", "a");
    if (!log_file) return;
    // 时间戳
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    fprintf(log_file, "[%04d-%02d-%02d %02d:%02d:%02d][TID:%lu][INFO] ",
        t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
        (unsigned long)GetCurrentThreadId());
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fclose(log_file);
}

DNSServer* createServer(void) {
    debug_log("开始创建服务器");
    DNSServer* server = (DNSServer*)malloc(sizeof(DNSServer));
    if (!server) {
        debug_log("内存分配失败");
        return NULL;
    }

    server->sockfd = INVALID_SOCKET;
    server->resolver = createResolver();
    server->initialized = 0;

    if (!server->resolver) {
        debug_log("创建解析器失败");
        free(server);
        return NULL;
    }

    debug_log("服务器创建成功");
    return server;
}

void destroyServer(DNSServer* server) {
    if (!server) return;

    if (server->sockfd != INVALID_SOCKET) {
        closesocket(server->sockfd);
    }
    if (server->initialized) {
        WSACleanup();
    }
    if (server->resolver) {
        destroyResolver(server->resolver);
    }
    free(server);
}

int initServer(DNSServer* server, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return 0;
    }
    server->initialized = 1;

    server->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server->sockfd == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(server->sockfd, (struct sockaddr*)&serverAddr, 
             sizeof(serverAddr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed: %d\n", WSAGetLastError());
        return 0;
    }

    printf("DNS server running on port %d\n", port);
    return 1;
}

int loadDomainFile(DNSServer* server, const char* filename) {
    if (!loadDomainMap(server->resolver, filename)) {
        fprintf(stderr, "Failed to load domain-IP mapping file: %s\n", filename);
        return 0;
    }
    printf("Successfully loaded domain-IP mapping file\n");
    return 1;
}

// 查询处理线程函数
unsigned __stdcall queryHandler(void* arg) {
    struct {
        DNSServer* server;
        char* buffer;
        size_t length;
        struct sockaddr_in clientAddr;
    }* params = (struct {
        DNSServer* server;
        char* buffer;
        size_t length;
        struct sockaddr_in clientAddr;
    }*)arg;

    handleQuery(params->server, params->buffer, params->length, &params->clientAddr);
    free(params->buffer);
    free(params);
    return 0;
}

// 中继功能：转发DNS请求到外部DNS服务器
int relayToExternalDNS(const char* request, int reqLen, char* response, int* respLen) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        debug_log("中继socket创建失败: %d", WSAGetLastError());
        return 0;
    }
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8"); // 可根据需要更换外部DNS

    int ret = sendto(sock, request, reqLen, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (ret == SOCKET_ERROR) {
        debug_log("中继sendto失败: %d", WSAGetLastError());
        closesocket(sock);
        return 0;
    }

    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int len = recvfrom(sock, response, 512, 0, (struct sockaddr*)&from, &fromlen);
    if (len == SOCKET_ERROR) {
        debug_log("中继recvfrom失败: %d", WSAGetLastError());
        closesocket(sock);
        return 0;
    }
    closesocket(sock);
    *respLen = len;
    return 1;
}

void handleQuery(DNSServer* server, const char* buffer, size_t length, 
                const struct sockaddr_in* clientAddr) {
    debug_log("开始处理查询");
    
    if (!server || !buffer || !clientAddr) {
        debug_log("无效的参数");
        return;
    }

    if (length < sizeof(struct DNSHeader)) {
        debug_log("DNS查询包太短");
        return;
    }

    uint16_t originalId = ntohs(((struct DNSHeader*)buffer)->id);
    char* domain = extractDomain(buffer, length);

    if (!domain) {
        debug_log("无法提取域名");
        return;
    }

    debug_log("查询域名: %s", domain);

    int isBlocked = 0;
    char* ip = resolveLocally(server->resolver, domain, &isBlocked);
    char* response = NULL;
    size_t responseLength = 0;

    if (isBlocked) {
        debug_log("域名被屏蔽: %s", domain);
        response = buildDNSResponse(originalId, domain, "", 1, &responseLength);
    } else if (ip) {
        debug_log("本地解析: %s -> %s", domain, ip);
        response = buildDNSResponse(originalId, domain, ip, 0, &responseLength);
        free(ip);
    } else {
        debug_log("转发查询: %s", domain);
        // 新增：真正的中继功能
        char relayResp[512];
        int relayLen = 0;
        if (relayToExternalDNS(buffer, (int)length, relayResp, &relayLen)) {
            debug_log("已中继外部DNS响应，长度: %d", relayLen);
            sendto(server->sockfd, relayResp, relayLen, 0, (struct sockaddr*)clientAddr, sizeof(*clientAddr));
            free(domain);
            debug_log("查询处理完成");
            return;
        } else {
            debug_log("中继外部DNS失败: %s", domain);
            response = buildDNSResponse(originalId, domain, "", 1, &responseLength);
        }
    }

    if (response) {
        debug_log("发送响应");
        int sent = sendto(server->sockfd, response, (int)responseLength, 0,
                         (struct sockaddr*)clientAddr, sizeof(*clientAddr));
        if (sent == SOCKET_ERROR) {
            debug_log("发送响应失败: %d", WSAGetLastError());
        }
        free(response);
    }

    free(domain);
    debug_log("查询处理完成");
}

int startServer(DNSServer* server) {
    if (!server) {
        debug_log("服务器未初始化");
        return 0;
    }

    debug_log("服务器开始监听");
    
    while (1) {
        char* buffer = (char*)malloc(1024);
        if (!buffer) {
            debug_log("内存分配失败");
            continue;
        }

        struct sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);

        debug_log("等待接收数据");
        int recvLen = recvfrom(server->sockfd, buffer, 1024, 0,
                              (struct sockaddr*)&clientAddr, &clientLen);
        if (recvLen == SOCKET_ERROR) {
            debug_log("接收数据失败: %d", WSAGetLastError());
            free(buffer);
            continue;
        }

        if (recvLen == 0) {
            debug_log("收到空数据包");
            free(buffer);
            continue;
        }

        debug_log("收到数据包，长度: %d", recvLen);
        debug_log_hex("收到DNS请求", buffer, recvLen);

        // 创建查询处理线程
        struct {
            DNSServer* server;
            char* buffer;
            size_t length;
            struct sockaddr_in clientAddr;
        }* params = (struct {
            DNSServer* server;
            char* buffer;
            size_t length;
            struct sockaddr_in clientAddr;
        }*)malloc(sizeof(*params));

        if (!params) {
            debug_log("内存分配失败");
            free(buffer);
            continue;
        }

        params->server = server;
        params->buffer = buffer;
        params->length = recvLen;
        params->clientAddr = clientAddr;

        debug_log("创建处理线程");
        HANDLE thread = (HANDLE)_beginthreadex(NULL, 0, queryHandler, params, 0, NULL);
        if (!thread) {
            debug_log("创建线程失败");
            free(params);
            free(buffer);
            continue;
        }
        CloseHandle(thread);
    }
    return 1;
} 
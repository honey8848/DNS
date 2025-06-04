#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <cstring>
#include <winsock2.h>
#include <thread>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

struct DNSHeader {
    // DNS 报文头部结构
    uint16_t id;       // 标识符
    uint16_t flags;    // 标志字段
    uint16_t qdcount;  // 问题数
    uint16_t ancount;  // 回答数
    uint16_t nscount;  // 授权记录数
    uint16_t arcount;  // 附加记录数
};

map<string, string> domainIPMap;
mutex mapMutex;

void loadDomainMap(const string& filename) {
    // 从文件加载域名到 IP 的映射
    ifstream file(filename);
    string line, domain, ip;

    lock_guard<mutex> lock(mapMutex);
    domainIPMap.clear();

    while (getline(file, line)) {
        size_t pos = line.find(' ');
        if (pos != string::npos) {
            ip = line.substr(0, pos);
            domain = line.substr(pos + 1);
            domainIPMap[domain] = ip;
        }
    }
}

string extractDomain(const char* buffer, size_t length) {
    // 从 DNS 查询报文中提取域名
    string domain;
    size_t pos = 12; // DNS 报文头部长度为 12 字节

    while (pos < length && buffer[pos] != 0) {
        uint8_t labelLen = buffer[pos++]; // 获取标签长度
        if (pos + labelLen > length) break;

        domain.append(buffer + pos, labelLen); // 添加标签到域名
        domain.append(".");
        pos += labelLen;
    }

    if (!domain.empty()) {
        domain.pop_back(); // 移除末尾的多余点
    }

    return domain;
}

vector<char> buildDNSResponse(uint16_t id, const string& domain, const string& ip, bool isError) {
    // 构建 DNS 响应报文
    vector<char> response;
    DNSHeader header;

    // 设置 DNS 报文头部
    header.id = htons(id);
    header.flags = htons(0x8180); // 标志字段：标准查询响应，无错误
    header.qdcount = htons(1);   // 问题数为 1
    header.ancount = htons(isError ? 0 : 1); // 回答数
    header.nscount = htons(0);   // 授权记录数
    header.arcount = htons(0);   // 附加记录数

    response.insert(response.end(), (char*)&header, (char*)&header + sizeof(header));

    // 构建问题部分
    size_t domainStart = response.size();
    size_t start = 0;
    size_t end = domain.find('.');

    while (end != string::npos) {
        string label = domain.substr(start, end - start);
        response.push_back(label.length());
        response.insert(response.end(), label.begin(), label.end());
        start = end + 1;
        end = domain.find('.', start);
    }

    string lastLabel = domain.substr(start);
    response.push_back(lastLabel.length());
    response.insert(response.end(), lastLabel.begin(), lastLabel.end());
    response.push_back(0);

    uint16_t qtype = htons(1);
    uint16_t qclass = htons(1);
    response.insert(response.end(), (char*)&qtype, (char*)&qtype + 2);
    response.insert(response.end(), (char*)&qclass, (char*)&qclass + 2);

    if (!isError) {
        // 构建回答部分
        uint16_t namePtr = htons(0xC000 | domainStart); // 指针指向问题部分的域名
        response.insert(response.end(), (char*)&namePtr, (char*)&namePtr + 2);
        response.insert(response.end(), (char*)&qtype, (char*)&qtype + 2);
        response.insert(response.end(), (char*)&qclass, (char*)&qclass + 2);

        uint32_t ttl = htonl(300);
        response.insert(response.end(), (char*)&ttl, (char*)&ttl + 4);

        uint16_t rdlength = htons(4);
        response.insert(response.end(), (char*)&rdlength, (char*)&rdlength + 2);

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

string queryExternalDNS(const string& domain) {
    // 查询外部 DNS 服务器获取域名对应的 IP 地址
    struct hostent* he = gethostbyname(domain.c_str());
    if (he == nullptr || he->h_addr_list[0] == nullptr) {
        return "";
    }

    char* ipStr = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    if (!ipStr) {
        return "";
    }

    return string(ipStr);
}

void handleDNSQuery(SOCKET clientSocket, const char* buffer, size_t length, const sockaddr_in& clientAddr) {
    // 处理收到的 DNS 查询
    uint16_t originalId = ntohs(((DNSHeader*)buffer)->id); // 获取查询 ID
    string domain = extractDomain(buffer, length); // 提取域名

    if (domain.empty()) {
        cerr << "Invalid DNS query" << endl;
        return;
    }

    cout << "Query for: " << domain << endl;

    string ip;
    bool isBlocked = false;

    {
        lock_guard<mutex> lock(mapMutex); // 加锁访问共享资源
        auto it = domainIPMap.find(domain);
        if (it != domainIPMap.end()) {
            ip = it->second;
            if (ip == "0.0.0.0") {
                isBlocked = true; // 检测是否为被阻止的域名
            }
        }
    }

    vector<char> response;

    if (isBlocked) {
        // 被阻止的域名
        cout << "Blocked domain: " << domain << endl;
        response = buildDNSResponse(originalId, domain, "", true);
    } else if (!ip.empty()) {
        // 本地解析
        cout << "Local resolution: " << domain << " -> " << ip << endl;
        response = buildDNSResponse(originalId, domain, ip, false);
    } else {
        // 转发查询到外部 DNS
        cout << "Relaying query for: " << domain << endl;
        ip = queryExternalDNS(domain);

        if (!ip.empty()) {
            cout << "External resolution: " << domain << " -> " << ip << endl;
            response = buildDNSResponse(originalId, domain, ip, false);

            lock_guard<mutex> lock(mapMutex);
            domainIPMap[domain] = ip; // 缓存外部解析结果
        } else {
            cout << "Domain not found: " << domain << endl;
            response = buildDNSResponse(originalId, domain, "", true);
        }
    }

    sendto(clientSocket, response.data(), (int)response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
}

int main(int argc, char* argv[]) {
    // 主函数：初始化服务器并处理 DNS 查询
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <port> <domain-ip-file>" << endl;
        return 0;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed: " << WSAGetLastError() << endl;
        return 0;
    }

    int port = atoi(argv[1]); // 获取端口号
    string domainFile = argv[2]; // 获取域名-IP 映射文件路径

    loadDomainMap(domainFile); // 加载域名-IP 映射
    cout << "Loaded " << domainIPMap.size() << " domain-IP mappings" << endl;

    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // 创建 UDP 套接字
    if (sockfd == INVALID_SOCKET) {
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
        WSACleanup();
        return 0;
    }

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        closesocket(sockfd);
        WSACleanup();
        return 0;
    }

    cout << "DNS server running on port " << port << endl;

    while (true) {
        char buffer[1024];
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);

        int recvLen = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&clientAddr, &clientLen);
        if (recvLen == SOCKET_ERROR) {
            cerr << "recvfrom failed: " << WSAGetLastError() << endl;
            continue;
        }

        thread(handleDNSQuery, sockfd, buffer, recvLen, clientAddr).detach(); // 启动新线程处理查询
    }

    closesocket(sockfd);
    WSACleanup();
    return 0;
}

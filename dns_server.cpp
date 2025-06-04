#include "dns_server.h"
#include "dns_message.h"
#include <iostream>
#include <thread>

using namespace std;

DNSServer::DNSServer() : sockfd(INVALID_SOCKET), initialized(false) {}

DNSServer::~DNSServer() {
    if (sockfd != INVALID_SOCKET) {
        closesocket(sockfd);
    }
    if (initialized) {
        WSACleanup();
    }
}

bool DNSServer::init(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed: " << WSAGetLastError() << endl;
        return false;
    }
    initialized = true;

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == INVALID_SOCKET) {
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
        return false;
    }

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        return false;
    }

    cout << "DNS server running on port " << port << endl;
    return true;
}

bool DNSServer::loadDomainFile(const string& filename) {
    if (!resolver.loadDomainMap(filename)) {
        cerr << "Failed to load domain-IP mapping file: " << filename << endl;
        return false;
    }
    cout << "Successfully loaded domain-IP mapping file" << endl;
    return true;
}

void DNSServer::handleQuery(const char* buffer, size_t length, const sockaddr_in& clientAddr) {
    uint16_t originalId = ntohs(((DNSHeader*)buffer)->id);
    string domain = extractDomain(buffer, length);

    if (domain.empty()) {
        cerr << "Invalid DNS query" << endl;
        return;
    }

    cout << "Query for: " << domain << endl;

    bool isBlocked = false;
    string ip = resolver.resolveLocally(domain, isBlocked);
    vector<char> response;

    if (isBlocked) {
        cout << "Blocked domain: " << domain << endl;
        response = buildDNSResponse(originalId, domain, "", true);
    } else if (!ip.empty()) {
        cout << "Local resolution: " << domain << " -> " << ip << endl;
        response = buildDNSResponse(originalId, domain, ip, false);
    } else {
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

    sendto(sockfd, response.data(), (int)response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
}

bool DNSServer::start() {
    while (true) {
        char buffer[1024];
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);

        int recvLen = recvfrom(sockfd, buffer, sizeof(buffer), 0, (sockaddr*)&clientAddr, &clientLen);
        if (recvLen == SOCKET_ERROR) {
            cerr << "recvfrom failed: " << WSAGetLastError() << endl;
            continue;
        }

        thread(&DNSServer::handleQuery, this, buffer, recvLen, clientAddr).detach();
    }
    return true;
} 
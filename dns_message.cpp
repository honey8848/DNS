#include "dns_message.h"
#include <winsock2.h>
#include <iostream>

using namespace std;

string extractDomain(const char* buffer, size_t length) {
    string domain;
    size_t pos = 12; // DNS 报文头部长度为 12 字节

    while (pos < length && buffer[pos] != 0) {
        uint8_t labelLen = buffer[pos++];
        if (pos + labelLen > length) break;

        domain.append(buffer + pos, labelLen);
        domain.append(".");
        pos += labelLen;
    }

    if (!domain.empty()) {
        domain.pop_back();
    }

    return domain;
}

vector<char> buildDNSResponse(uint16_t id, const string& domain, const string& ip, bool isError) {
    vector<char> response;
    DNSHeader header;

    // 设置 DNS 报文头部
    header.id = htons(id);
    header.flags = htons(0x8180);
    header.qdcount = htons(1);
    header.ancount = htons(isError ? 0 : 1);
    header.nscount = htons(0);
    header.arcount = htons(0);

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
        uint16_t namePtr = htons(0xC000 | domainStart);
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
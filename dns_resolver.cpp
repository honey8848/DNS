#include "dns_resolver.h"
#include <fstream>
#include <winsock2.h>
#include <iostream>

using namespace std;

DNSResolver::DNSResolver() {}

bool DNSResolver::loadDomainMap(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

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

    return true;
}

string DNSResolver::resolveLocally(const string& domain, bool& isBlocked) {
    lock_guard<mutex> lock(mapMutex);
    auto it = domainIPMap.find(domain);
    if (it != domainIPMap.end()) {
        isBlocked = (it->second == "0.0.0.0");
        return it->second;
    }
    isBlocked = false;
    return "";
}

string DNSResolver::queryExternalDNS(const string& domain) {
    struct hostent* he = gethostbyname(domain.c_str());
    if (he == nullptr || he->h_addr_list[0] == nullptr) {
        return "";
    }

    char* ipStr = inet_ntoa(*(struct in_addr*)he->h_addr_list[0]);
    return ipStr ? string(ipStr) : "";
}

void DNSResolver::cacheExternalResult(const string& domain, const string& ip) {
    lock_guard<mutex> lock(mapMutex);
    domainIPMap[domain] = ip;
} 
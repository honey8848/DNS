#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

#include <string>
#include <vector>
#include "dns_types.h"

// DNS报文处理相关函数声明
std::string extractDomain(const char* buffer, size_t length);
std::vector<char> buildDNSResponse(uint16_t id, const std::string& domain, const std::string& ip, bool isError);

#endif // DNS_MESSAGE_H 
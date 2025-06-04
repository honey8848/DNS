#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <winsock2.h>
#include "dns_resolver.h"

class DNSServer {
public:
    DNSServer();
    ~DNSServer();
    bool init(int port);
    bool loadDomainFile(const std::string& filename);
    bool start();
    void handleQuery(const char* buffer, size_t length, const sockaddr_in& clientAddr);

private:
    SOCKET sockfd;
    DNSResolver resolver;
    bool initialized;
};

#endif // DNS_SERVER_H 
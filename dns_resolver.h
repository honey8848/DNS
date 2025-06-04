#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <string>
#include <map>
#include <mutex>

class DNSResolver {
public:
    DNSResolver();
    bool loadDomainMap(const std::string& filename);
    std::string resolveLocally(const std::string& domain, bool& isBlocked);
    std::string queryExternalDNS(const std::string& domain);
    void cacheExternalResult(const std::string& domain, const std::string& ip);

private:
    std::map<std::string, std::string> domainIPMap;
    std::mutex mapMutex;
};

#endif // DNS_RESOLVER_H 
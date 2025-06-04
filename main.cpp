#include "dns_server.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <port> <domain-ip-file>" << endl;
        return 0;
    }

    int port = atoi(argv[1]);
    string domainFile = argv[2];

    DNSServer server;
    if (!server.init(port)) {
        cerr << "Failed to initialize DNS server" << endl;
        return 1;
    }

    if (!server.loadDomainFile(domainFile)) {
        cerr << "Failed to load domain file" << endl;
        return 1;
    }

    server.start();
    return 0;
} 
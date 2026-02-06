#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <iomanip>
#include <cstring>
#include <cstddef>
#include <chrono>

// Network headers
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

std::mutex cout_mutex;

class QuickLog {
private:
    static void printBanner() {
        std::cout << "\033[H\033[J"; // Clear screen

        const std::string quicklog[] = {
            "   ____        _      _    _",
            "  / __ \\      (_)    | |  | |",
            " | |  | |_   _ _  ___| | _| |     ___   __ _",
            " | |  | | | | | |/ __| |/ / |    / _ \\ / _` |",
            " | |__| | |_| | | (__|   <| |___| (_) | (_| |",
            "  \\___\\_\\\\__,_|_|\\___|_|\\_\\______\\___/ \\__, |",
            "                                        __/ |",
            "                                       |___/ "
        };

        const std::string sleepingCat[] = {
            "   |\\      _,,,---,,_",
            "  /,`.-'`'    -.  ;-;;,_",
            " |,4-  ) )-,_. ,\\ (  `'-'",
            "'---''(_/--'  `-'\\_)"
        };

        constexpr ssize_t qLogRows = 8;
        constexpr ssize_t catRows = 4;
        constexpr ssize_t catStartRow = qLogRows - catRows;

        for (ssize_t i = 0; i < qLogRows; ++i) {
            const int columnWidth = 50;
            std::cout << BLUE << quicklog[i] << RESET;
            auto currentLineLength = static_cast<int>(quicklog[i].length());

            for (int j = 0; j < (columnWidth - currentLineLength); ++j)
                std::cout << " ";

            if (i >= catStartRow) {
                std::cout << MAGENTA << sleepingCat[i - catStartRow] << RESET;
            }
            std::cout << '\n';
        }

        std::cout << CYAN << "\n  Network Recon & DNS Toolkit for macOS\n" << RESET;
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
    }

    static void printMenu() {
        std::cout << BOLD << "  [1]" << RESET << " \xF0\x9F\x94\x8D Network Scanner\n";
        std::cout << BOLD << "  [2]" << RESET << " \xF0\x9F\x8C\x90 DNS Lookup\n";
        std::cout << BOLD << "  [3]" << RESET << " \xF0\x9F\x94\x84 Reverse DNS Lookup\n";
        std::cout << BOLD << "  [4]" << RESET << " \xF0\x9F\x93\xA1 DNS Propagation Check\n";
        std::cout << BOLD << "  [5]" << RESET << " \xF0\x9F\x8E\xAF Port Scanner\n";
        std::cout << BOLD << "  [6]" << RESET << " \xF0\x9F\x93\x8A Network Interfaces\n";
        std::cout << BOLD << "  [7]" << RESET << " \xF0\x9F\x9A\x80 Quick Ping Sweep\n";
        std::cout << BOLD << "  [0]" << RESET << " \xE2\x9D\x8C Exit\n\n";
        std::cout << YELLOW << "  Select option: " << RESET;
    }

    static std::string getLocalIP() {
        struct ifaddrs *ifaddr;
        char host[NI_MAXHOST];
        std::string localIP;

        if (getifaddrs(&ifaddr) == -1) {
            return "";
        }

        for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            int family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) {
                int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                  host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
                if (s == 0) {
                    std::string ifname(ifa->ifa_name);
                    std::string ip(host);

                    // Prefer en0 (WiFi) or en1 (Ethernet) on macOS
                    if ((ifname == "en0" || ifname == "en1") && ip != "127.0.0.1") {
                        localIP = ip;
                        break;
                    }
                }
            }
        }

        freeifaddrs(ifaddr);
        return localIP;
    }

    static bool isPortOpen(const std::string& ip, int port, int timeout_ms = 500) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;

        // Set non-blocking
        fcntl(sock, F_SETFL, O_NONBLOCK);

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        struct timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        bool isOpen = false;
        if (select(sock + 1, nullptr, &fdset, nullptr, &tv) > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
            isOpen = (error == 0);
        }

        close(sock);
        return isOpen;
    }

    static std::string dnsLookup(const std::string& hostname) {
        struct addrinfo hints{};
        struct addrinfo *result;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
            return "Failed";
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(reinterpret_cast<struct sockaddr_in*>(result->ai_addr)->sin_addr),
                 ip, INET_ADDRSTRLEN);

        freeaddrinfo(result);
        return std::string(ip);
    }

    static std::string reverseDNS(const std::string& ip) {
        struct sockaddr_in sa{};
        char host[NI_MAXHOST];

        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa), host, sizeof(host),
                       nullptr, 0, 0) != 0) {
            return "No PTR record";
        }

        return std::string(host);
    }

    void networkScanner() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x94\x8D NETWORK SCANNER" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string localIP = getLocalIP();
        if (localIP.empty()) {
            std::cout << RED << "  \xE2\x9D\x8C Could not determine local IP\n" << RESET;
            return;
        }

        std::cout << "  Local IP: " << GREEN << localIP << RESET << "\n\n";

        // Extract network prefix
        ssize_t lastDot = localIP.find_last_of('.');
        std::string networkPrefix = localIP.substr(0, lastDot + 1);

        std::cout << "  Scanning " << YELLOW << networkPrefix << "0/24" << RESET << "...\n\n";
        std::cout << "  " << std::setw(15) << std::left << "IP Address"
                  << std::setw(30) << "Hostname"
                  << "Status\n";
        std::cout << "  " << std::string(60, '-') << "\n";

        std::vector<std::thread> threads;

        for (int i = 1; i < 255; i++) {
            threads.push_back(std::thread([this, networkPrefix, i]() {
                std::string ip = networkPrefix + std::to_string(i);

                // Quick ICMP check would be better, but needs raw sockets (root)
                // So we'll check common ports instead
                bool alive = isPortOpen(ip, 80, 200) ||
                           isPortOpen(ip, 443, 200) ||
                           isPortOpen(ip, 22, 200);

                if (alive) {
                    std::string hostname = reverseDNS(ip);

                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "  " << GREEN << std::setw(15) << std::left << ip << RESET
                             << std::setw(30) << hostname.substr(0, 28)
                             << GREEN << "\xE2\x97\x8F Online" << RESET << "\n";
                }
            }));

            // Limit concurrent threads
            if (threads.size() >= 50) {
                for (auto& t : threads) t.join();
                threads.clear();
            }
        }

        for (auto& t : threads) t.join();

        std::cout << "\n  " << GREEN << "\xE2\x9C\x93 Scan complete!" << RESET << "\n";
    }

    static void dnsLookupTool() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x8C\x90 DNS LOOKUP" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string hostname;
        std::cout << "  Enter hostname: ";
        std::cin >> hostname;

        std::cout << "\n  Resolving " << YELLOW << hostname << RESET << "...\n\n";

        std::string ip = dnsLookup(hostname);

        if (ip != "Failed") {
            std::cout << "  " << GREEN << "\xE2\x9C\x93 " << hostname << " -> " << ip << RESET << "\n";
        } else {
            std::cout << "  " << RED << "\xE2\x9C\x97 Failed to resolve " << hostname << RESET << "\n";
        }
    }

    static void reverseDNSTool() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x94\x84 REVERSE DNS LOOKUP" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string ip;
        std::cout << "  Enter IP address: ";
        std::cin >> ip;

        std::cout << "\n  Looking up " << YELLOW << ip << RESET << "...\n\n";

        std::string hostname = reverseDNS(ip);

        std::cout << "  " << GREEN << "\xE2\x9C\x93 " << ip << " -> " << hostname << RESET << "\n";
    }

    static void dnsPropagationCheck() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x93\xA1 DNS PROPAGATION CHECK" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string hostname;
        std::cout << "  Enter hostname: ";
        std::cin >> hostname;

        const std::vector<std::pair<std::string, std::string>> dnsServers = {
            {"Google", "8.8.8.8"},
            {"Cloudflare", "1.1.1.1"},
            {"OpenDNS", "208.67.222.222"},
            {"Quad9", "9.9.9.9"}
        };

        std::cout << "\n  Checking DNS propagation for " << YELLOW << hostname << RESET << "...\n\n";
        std::cout << "  " << std::setw(15) << std::left << "DNS Server"
                  << std::setw(20) << "Provider"
                  << "Result\n";
        std::cout << "  " << std::string(60, '-') << "\n";

        for (const auto& server : dnsServers) {
            // Note: This is a simplified version. Real DNS propagation check
            // would query specific DNS servers directly
            std::string ip = dnsLookup(hostname);

            std::cout << "  " << std::setw(15) << std::left << server.second
                     << std::setw(20) << server.first
                     << GREEN << ip << RESET << "\n";
        }

        std::cout << "\n  " << YELLOW << "\xE2\x9A\xA0 Note: Using system resolver. Install 'dig' for true propagation checks." << RESET << "\n";
    }

    static void portScanner() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x8E\xAF PORT SCANNER" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string target;
        std::cout << "  Enter target IP/hostname: ";
        std::cin >> target;

        // Resolve if hostname
        std::string ip = target;
        if (target.find_first_not_of("0123456789.") != std::string::npos) {
            ip = dnsLookup(target);
            if (ip == "Failed") {
                std::cout << RED << "  \xE2\x9C\x97 Could not resolve hostname\n" << RESET;
                return;
            }
        }

        std::cout << "\n  Scanning common ports on " << YELLOW << ip << RESET << "...\n\n";
        std::cout << "  " << CYAN << "  (Using 3 second timeout per port for reliability)\n" << RESET;

        const std::vector<std::pair<int, std::string>> commonPorts = {
            {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
            {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
            {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"}, {3389, "RDP"},
            {5432, "PostgreSQL"}, {5900, "VNC"}, {8080, "HTTP-Alt"}, {8443, "HTTPS-Alt"}
        };

        std::cout << "\n  " << std::setw(8) << "Port"
                  << std::setw(15) << "Service"
                  << "Status\n";
        std::cout << "  " << std::string(40, '-') << "\n";

        for (const auto& port : commonPorts) {
            // Use 3 second timeout for large sites with firewalls
            bool open = isPortOpen(ip, port.first, 3000);

            std::cout << "  " << std::setw(8) << port.first
                     << std::setw(15) << port.second;

            if (open) {
                std::cout << GREEN << "\xE2\x97\x8F OPEN" << RESET << "\n";
            } else {
                std::cout << RED << "\xE2\x9C\x97 Closed" << RESET << "\n";
            }

            // Small delay between port checks to avoid rate limiting
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        std::cout << "\n  " << GREEN << "\xE2\x9C\x93 Scan complete!" << RESET << "\n";
    }

    static void showInterfaces() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x93\x8A NETWORK INTERFACES" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        struct ifaddrs *ifaddr;

        if (getifaddrs(&ifaddr) == -1) {
            std::cout << RED << "  \xE2\x9C\x97 Failed to get interfaces\n" << RESET;
            return;
        }

        std::cout << "  " << std::setw(10) << std::left << "Interface"
                  << std::setw(18) << "IPv4 Address"
                  << "Status\n";
        std::cout << "  " << std::string(50, '-') << "\n";

        for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                char host[NI_MAXHOST];
                getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                          host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);

                std::cout << "  " << std::setw(10) << std::left << ifa->ifa_name
                         << std::setw(18) << host;

                if (ifa->ifa_flags & IFF_UP) {
                    std::cout << GREEN << "\xE2\x97\x8F UP" << RESET;
                } else {
                    std::cout << RED << "\xE2\x9C\x97 DOWN" << RESET;
                }
                std::cout << "\n";
            }
        }

        freeifaddrs(ifaddr);
    }

    void quickPingSweep() {
        std::cout << "\n" << CYAN << BOLD << "  \xF0\x9F\x9A\x80 QUICK PING SWEEP" << RESET << "\n";
        std::cout << "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

        std::string localIP = getLocalIP();
        if (localIP.empty()) {
            std::cout << RED << "  \xE2\x9D\x8C Could not determine local IP\n" << RESET;
            return;
        }

        ssize_t lastDot = localIP.find_last_of('.');
        std::string networkPrefix = localIP.substr(0, lastDot + 1);

        std::cout << "  Fast sweep of " << YELLOW << networkPrefix << "0/24" << RESET << "\n\n";

        std::vector<std::string> aliveHosts;
        std::vector<std::thread> threads;

        for (int i = 1; i < 255; i++) {
            threads.push_back(std::thread([this, networkPrefix, i, &aliveHosts]() {
                std::string ip = networkPrefix + std::to_string(i);
                
                if (isPortOpen(ip, 80, 100) || isPortOpen(ip, 443, 100)) {
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    aliveHosts.push_back(ip);
                    std::cout << "  " << GREEN << "\xE2\x97\x8F " << ip << RESET << "\n";
                }
            }));

            if (threads.size() >= 100) {
                for (auto& t : threads) t.join();
                threads.clear();
            }
        }

        for (auto& t : threads) t.join();

        std::cout << "\n  Found " << GREEN << aliveHosts.size() << " active hosts" << RESET << "\n";
    }

public:
    void run() {
        while (true) {
            printBanner();
            printMenu();

            int choice;
            std::cin >> choice;

            switch (choice) {
                case 1:
                    networkScanner();
                    break;
                case 2:
                    dnsLookupTool();
                    break;
                case 3:
                    reverseDNSTool();
                    break;
                case 4:
                    dnsPropagationCheck();
                    break;
                case 5:
                    portScanner();
                    break;
                case 6:
                    showInterfaces();
                    break;
                case 7:
                    quickPingSweep();
                    break;
                case 0:
                    std::cout << "\n" << MAGENTA << "  Goodbye!" << RESET;
                    return;
                default:
                    std::cout << RED << "\n  Invalid option!\n" << RESET;
            }

            std::cout << "\n  Press Enter to continue...";
            std::cin.ignore();
            std::cin.get();
        }
    }
};

int main() {
    QuickLog app;
    app.run();
    return 0;
}
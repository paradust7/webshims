/*
MIT License

Copyright (c) 2022 paradust7

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once

#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>

namespace emsocket {

class SocketAddr {
public:
    SocketAddr() {
        clear();
    }

    SocketAddr(const std::string &ip, uint16_t port) {
        clear();
        setIP(ip);
        setPort(port);
    }

    SocketAddr(const struct sockaddr *addr, socklen_t addrlen) {
        clear();
        if (addr->sa_family == AF_INET && addrlen >= sizeof(sin)) {
            memcpy(&sin, addr, sizeof(sin));
        }
    }

    bool isIPv4() const {
        return true; // Only one supported at the moment
    }

    bool isIPv6() const {
        return false;
    }

    std::string getIP() const {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sin.sin_addr), buf, sizeof(buf));
        return std::string(buf);
    }

    bool setIP(std::string ip) {
        if (1 == inet_pton(AF_INET, ip.c_str(), &(sin.sin_addr))) {
            sin.sin_family = AF_INET;
            return true; // success
        }
        return false; // fail
    }

    uint16_t getPort() const {
        return ntohs(sin.sin_port);
    }

    void setPort(uint16_t port) {
        sin.sin_port = htons(port);
    }

    SocketAddr(const SocketAddr &o) {
        memcpy(&sin, &o.sin, sizeof(sin));
    }

    SocketAddr& operator=(const SocketAddr &o) {
        memcpy(&sin, &o.sin, sizeof(sin));
        return *this;
    }

    void clear() {
        memset(&sin, 0, sizeof(sin));
    }

    bool isLocalHost() const {
        return (sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    }

    void copyTo(struct sockaddr *addr, socklen_t *addr_len) const {
        if (!addr) {
                return;
        }
        memcpy(addr, &sin, std::min((size_t)*addr_len, sizeof(sin)));
        *addr_len = sizeof(sin);
    }

    bool operator==(const SocketAddr &o) const {
        return (
            sin.sin_family == o.sin.sin_family &&
            sin.sin_port == o.sin.sin_port &&
            sin.sin_addr.s_addr == o.sin.sin_addr.s_addr);
    }

    bool operator!=(const SocketAddr &o) const {
        return !(*this == o);
    }

    const struct sockaddr* sockaddr_ptr() {
        return (const struct sockaddr*)&sin;
    }

    socklen_t sockaddr_len() {
        return sizeof(sin);
    }

private:
    sockaddr_in sin;
};

static inline std::ostream& operator<<(std::ostream &os, const SocketAddr &addr) {
    os << addr.getIP() << ":" << addr.getPort();
    return os;
}

} // namespace

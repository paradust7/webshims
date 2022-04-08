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

#include <vector>
#include <list>
#include <string>
#include <mutex>
#include <atomic>
#include "SocketAddr.h"
#include "Link.h"
#include "Packet.h"

// This must match the same defines in emsocket.h
#define EMSOCKET_BASE_FD   512
#define EMSOCKET_MAX_FD    1024
#define EMSOCKET_NSOCKETS  (EMSOCKET_MAX_FD - EMSOCKET_BASE_FD)

namespace emsocket {

class VirtualSocket {
public:
    static VirtualSocket* allocate(bool udp);
    static VirtualSocket* get(int fd);
    int fd() const { return fd_; }
    bool isUDP() const { return is_udp; }
    bool isBlocking() const { return is_blocking; }
    void setBlocking(bool value) { is_blocking = value; }
    bool isBound() const { return bindAddr.getPort() != 0; }
    bool bind(const SocketAddr &addr);
    const SocketAddr& getBindAddr() { return bindAddr; }
    const SocketAddr& getRemoteAddr() { return remoteAddr; }

    bool isConnected() const { return is_connected; }
    bool isShutdown() const { return is_shutdown; }

    // This should only be called holding the lock
    // (e.g. inside the predicate for waitFor)
    bool hasData() const;

    bool canBlock() const;
    void waitForData();
    void waitForConnect();
    static void waitFor(
        const std::vector<VirtualSocket*> &waitlist,
        const std::function<bool(void)>& predicate,
        int64_t timeout);

    bool startConnect(const SocketAddr &dest);

    // Stream read/write. Always non-blocking.
    ssize_t read(void *buf, size_t n);
    void write(const void *buf, size_t n);

    // Datagram read/write. Always non-blocking
    ssize_t recvfrom(void *buf, size_t n, SocketAddr *from);
    void sendto(const void *buf, size_t n, const SocketAddr& to);

    void close();

    void linkConnected();
    void linkShutdown();
    void linkReceived(const SocketAddr &addr, const void *buf, size_t n);

private:
    VirtualSocket()
        : fd_(-1) {
    }
    VirtualSocket(const VirtualSocket &) = delete;
    VirtualSocket& operator=(const VirtualSocket &) = delete;
    void reset();
    void open(int fd, bool udp);

    int fd_;
    bool is_udp;
    bool is_blocking;
    std::atomic<bool> is_connected;
    std::atomic<bool> is_shutdown;
    SocketAddr bindAddr;
    SocketAddr remoteAddr;
    Link *link;

    mutable std::mutex recvbufMutex; // only protects recvbuf
    std::list<Packet> recvbuf;

    static VirtualSocket sockets[EMSOCKET_NSOCKETS];
};

} // namespace

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
#define EMSOCKET_INTERNAL
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <random>
#include <cassert>
#include <emscripten/threading.h>
#include "VirtualSocket.h"
#include "ProxyLink.h"

namespace emsocket {

// This mutex protects:
//  1) Allocating a new socket
//  2) Adding/removing a port binding
//  3) Adding/removing packets from a receive buffer
//
// The VirtualSocket's themselves are not protected by a mutex.
// POSIX sockets are not thread-safe, so it is assumed that
// every fd will be used only by a single thread at a time.
//
static std::mutex vs_mutex;
static std::condition_variable vs_event;
VirtualSocket VirtualSocket::sockets[EMSOCKET_NSOCKETS];
static std::unordered_map<uint16_t, VirtualSocket*> vs_port_map;

#define VSLOCK()   const std::lock_guard<std::mutex> lock(vs_mutex)

static std::random_device rd;

void VirtualSocket::open(int fd, bool udp) {
    assert(fd_ == -1);
    reset();
    fd_ = fd;
    is_udp = udp;
}

void VirtualSocket::reset() {
    fd_ = -1;
    is_connected = false;
    is_shutdown = false;
    is_blocking = true;
    bindAddr.clear();
    remoteAddr.clear();
    recvbuf.clear();
    link = nullptr;
}


void VirtualSocket::close() {
    VSLOCK();
    uint16_t port = bindAddr.getPort();
    if (link) {
        delete link;
        link = nullptr;
    }
    if (port != 0) {
        vs_port_map.erase(port);
    }
    reset();
}

void VirtualSocket::linkConnected() {
    is_connected = true;
    vs_event.notify_all();
}

void VirtualSocket::linkShutdown() {
    is_shutdown = true;
    vs_event.notify_all();
}

void VirtualSocket::linkReceived(const SocketAddr& addr, const void *buf, size_t n) {
    {
        VSLOCK();
        recvbuf.emplace_back(addr, buf, n);
    }
    vs_event.notify_all();
}

VirtualSocket* VirtualSocket::allocate(bool udp) {
    VSLOCK();
    for (int idx = 0; idx < EMSOCKET_NSOCKETS; idx++) {
        if (sockets[idx].fd_ == -1) {
            sockets[idx].open(EMSOCKET_BASE_FD + idx, udp);
            return &sockets[idx];
        }
    }
    return nullptr;
}

VirtualSocket* VirtualSocket::get(int fd) {
    if (fd < EMSOCKET_BASE_FD || fd >= EMSOCKET_MAX_FD) {
        return nullptr;
    }
    int idx = fd - EMSOCKET_BASE_FD;
    VirtualSocket* vs = &sockets[idx];
    assert(vs && vs->fd_ == fd);
    return vs;
}

bool VirtualSocket::bind(const SocketAddr& addr) {
    assert(bindAddr.getPort() == 0);
    VSLOCK();
    // TODO: Separate out TCP and UDP ports?
    uint16_t port = addr.getPort();
    if (port == 0) {
        std::default_random_engine engine(rd());
        std::uniform_int_distribution<int> randport(4096, 16384);
        do {
            port = randport(engine);
        } while (vs_port_map.count(port));
    } else if (vs_port_map.count(port)) {
        return false;
    }
    bindAddr = addr;
    bindAddr.setPort(port);
    vs_port_map[port] = this;
    return true;
}

bool VirtualSocket::canBlock() const {
    // Out of necessity, sockets in the main browser thread will
    // always act like non-blocking sockets.
    return is_blocking; // && !emscripten_is_main_browser_thread();
}

void VirtualSocket::waitForData() {
    VirtualSocket::waitFor([&]() {
        return !recvbuf.empty();
    }, -1);
}

void VirtualSocket::waitForConnect() {
    VirtualSocket::waitFor([&]() {
        return isConnected() || isShutdown();
    }, -1);
}

bool VirtualSocket::runWithLock(const std::function<bool(void)>& predicate) {
    std::unique_lock<std::mutex> lock(vs_mutex);
    return predicate();
}

void VirtualSocket::waitFor(const std::function<bool(void)>& predicate, int64_t timeout) {
    std::unique_lock<std::mutex> lock(vs_mutex);
    if (timeout < 0) {
        vs_event.wait(lock, predicate);
    } else {
        vs_event.wait_for(lock, std::chrono::milliseconds(timeout), predicate);
    }
}

bool VirtualSocket::startLocalConnect(uint16_t port) {
    std::cerr << "emsocket local TCP not yet supported" << std::endl;
    return false;
}

bool VirtualSocket::startProxyConnect(const std::string &proxyUrl, const SocketAddr &dest) {
    assert(!is_udp);
    assert(!link);
    assert(!is_connected);
    assert(!is_shutdown);
    assert(proxyUrl.size() > 0);
    if (!isBound()) {
        bind(SocketAddr()); // bind to random port
    }
    remoteAddr = dest;
    link = make_proxy_link(this, proxyUrl, dest, is_udp);
    return true;
}


// Stream read/write. Always non-blocking.
ssize_t VirtualSocket::read(void *buf, size_t n) {
    assert(!is_udp);
    VSLOCK();
    char *cbuf = (char*)buf;
    size_t pos = 0;
    while (!recvbuf.empty() && pos < n) {
        Packet pkt = std::move(recvbuf.front());
        recvbuf.pop_front();
        size_t take = std::min(n - pos, pkt.data.size());
        memcpy(&cbuf[pos], &pkt.data[0], take);
        pos += take;
        if (take < pkt.data.size()) {
            recvbuf.emplace_front(pkt.from, &pkt.data[take], pkt.data.size() - take);
            break;
        }
    }
    return pos;
}

void VirtualSocket::write(const void *buf, size_t n) {
    assert(!is_udp);
    assert(is_connected);
    if (link) {
        link->send(buf, n);
    }
}

// Datagram read/write. Always non-blocking
ssize_t VirtualSocket::recvfrom(void *buf, size_t n, SocketAddr *from) {
    assert(is_udp);
    VSLOCK();
    char *cbuf = (char*)buf;
    if (!recvbuf.empty()) {
        Packet pkt = std::move(recvbuf.front());
        recvbuf.pop_front();
        size_t take = std::min(n, pkt.data.size());
        memcpy(&cbuf[0], &pkt.data[0], take);
        *from = pkt.from;
        return take;
    }
    return 0;
}

void VirtualSocket::sendto(const void *buf, size_t n, const SocketAddr& to) {
    assert(is_udp);
    assert(isBound());
    SocketAddr sourceAddr("127.0.0.1", bindAddr.getPort());
    if (to.isLocalHost()) {
        bool sent = false;
        {
            VSLOCK();
            uint16_t port = to.getPort();
            auto it = vs_port_map.find(port);
            if (it != vs_port_map.end()) {
                it->second->recvbuf.emplace_back(sourceAddr, buf, n);
                sent = true;
            }
        }
        if (sent) {
            vs_event.notify_all();
        } else {
            std::cerr << "sendto going nowhere" << std::endl;
        }
        return;
    }
    // Proxying to external UDP not implemented yet
    abort();
}

} // namespace

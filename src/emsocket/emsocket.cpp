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

#include <deque>
#include <netinet/in.h>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <random>
#include <unordered_map>
#include <cerrno>
#include <mutex>
#include <condition_variable>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define EMSOCKET_INTERNAL
#include "emsocket.h"

// Browsers don't allow websocket servers, so simulate servers on `localhost` with a buffer instead.
static bool is_localhost(const struct sockaddr *addr, socklen_t addrlen) {
	assert(addr->sa_family == AF_INET);
	if (((sockaddr_in*)addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
		return true;
	}
	return false;
}

static uint16_t get_port(const struct sockaddr *addr, socklen_t addrlen) {
	assert(addr->sa_family == AF_INET);
        return ntohs(((sockaddr_in*)addr)->sin_port);
}

// sockfd -> receive packet buffer
struct pkt {
	uint16_t source_port;
	std::vector<char> data;

	pkt() = delete;
	pkt(const pkt &) = delete;
	pkt& operator=(const pkt &) = delete;

	pkt(uint16_t port, const char *buf, size_t len)
	: source_port(port), data(&buf[0], &buf[len]) { }
};

struct VirtualSocket {
	std::mutex mutex;
	std::condition_variable cv;
	bool open = true;
	uint16_t sport = 0;
	std::deque<pkt> recvbuf;
};

// TODO: Reuse socket ids to avoid blowing up select
#define BASE_SOCKET_ID   100

// Protects the maps and id generation
static std::mutex mutex;
static std::vector<VirtualSocket*> socket_map;
static std::unordered_map<uint16_t, VirtualSocket*> port_map;
static unsigned int seed = 0;
static std::default_random_engine generator;
static std::uniform_int_distribution<uint16_t> randport(4096, 32000);

// Must be called while holding mutex
static uint16_t random_port() {
	if (seed == 0) {
		seed = std::chrono::system_clock::now().time_since_epoch().count();
		generator.seed(seed);
	}
	uint16_t port;
	do {
		port = randport(generator);
	} while (port_map.count(port) != 0);
	return port;
}

static VirtualSocket *getvs(int sockfd) {
	assert(sockfd >= BASE_SOCKET_ID);
	int id = sockfd - BASE_SOCKET_ID;
	assert(id < socket_map.size());
	VirtualSocket* vs = socket_map[id];
	assert(vs && vs->open);
	return vs;
}


int emsocket_socket(int domain, int type, int protocol) {
	const std::lock_guard<std::mutex> lock(mutex);
	VirtualSocket* vs = new VirtualSocket();
	int id = socket_map.size();
	socket_map.push_back(vs);
	return BASE_SOCKET_ID + id;
}

int emsocket_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
	return -1;
}

int emsocket_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	const std::lock_guard<std::mutex> lock(mutex);
	auto vs = getvs(sockfd);
	assert(vs->sport == 0);
	uint16_t port = get_port(addr, addrlen);
	if (port == 0) {
		port = random_port();
	}
	if (port_map.count(port)) {
		errno = EADDRINUSE;
		return -1;
	}
	vs->sport = port;
	port_map[port] = vs;
	return 0;
}

ssize_t emsocket_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen) {
	if (!is_localhost(dest_addr, addrlen)) {
		// Sending to other than localhost not yet implemented
		return 0;
	}
	uint16_t source_port;
	uint16_t dest_port = get_port(dest_addr, addrlen);
	VirtualSocket* dest_vs = nullptr;
	{
		const std::lock_guard<std::mutex> lock(mutex);
		source_port = getvs(sockfd)->sport;
		auto it = port_map.find(dest_port);
		if (it != port_map.end()) {
			dest_vs = it->second;
		}
	}
	assert(source_port && "sendto before bind()");
	if (!dest_vs) {
		// Nothing is listening on localhost?
		return 0;
	}
	// Lock destination vs
	{
		const std::lock_guard<std::mutex> lock(dest_vs->mutex);
		dest_vs->recvbuf.emplace_back(source_port, (const char*)buf, len);
	}
	dest_vs->cv.notify_all();
	//std::cout << "sockfd=" << sockfd << " Sent packet of size " << len << std::endl;
	return len;
}

ssize_t emsocket_recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
	VirtualSocket *vs;
	{
		const std::lock_guard<std::mutex> lock(mutex);
		vs = getvs(sockfd);
	}
	// For now, this should never be called in a blocking situation.
	assert(vs->recvbuf.size() > 0);
	const std::lock_guard<std::mutex> lock(vs->mutex);
	const pkt &p = vs->recvbuf.front();
	ssize_t written = std::min(p.data.size(), len);
	bool truncated = (written != (ssize_t)p.data.size());
	memcpy(buf, &p.data[0], written);
	if (src_addr) {
		struct sockaddr_in ai = {0};
		ai.sin_family = AF_INET;
		ai.sin_port = htons(p.source_port);
		ai.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		memcpy(src_addr, &ai, std::min((size_t)*addrlen, sizeof(ai)));
		*addrlen = sizeof(ai);
	}
	vs->recvbuf.pop_front();
	if (truncated) errno = EMSGSIZE;
	//std::cout << "sockfd=" << sockfd << " Received packet of size " << written << std::endl;
	return written;
}

// Cheap hack
// Only supports select on a single fd
int emsocket_select(
		int nfds,
		fd_set *readfds,
		fd_set *writefds,
		fd_set *exceptfds,
		struct timeval *timeout) {
	int sockfd = nfds - 1;
	assert(FD_ISSET(sockfd, readfds));
	VirtualSocket *vs;
	{
		const std::lock_guard<std::mutex> lock(mutex);
		vs = getvs(sockfd);
	}
	std::unique_lock<std::mutex> lock(vs->mutex);

	if (timeout == NULL) {
		vs->cv.wait(lock, [&]{ return vs->recvbuf.size() > 0; });
	} else {
		long ms = (timeout->tv_sec * 1000) + (timeout->tv_usec / 1000);
		auto cvtimeout = std::chrono::milliseconds(ms);
		vs->cv.wait_for(lock, cvtimeout, [&]{ return vs->recvbuf.size() > 0; });
	}
	if (vs->recvbuf.size() == 0) {
		return 0;
	}
	return 1;
}

int emsocket_close(int sockfd) {
	const std::lock_guard<std::mutex> lock(mutex);
	auto vs = getvs(sockfd);
	if (vs->sport) {
		port_map.erase(vs->sport);
		vs->sport = 0;
	}
	vs->open = false;
	vs->recvbuf.clear();
	return 0;
}

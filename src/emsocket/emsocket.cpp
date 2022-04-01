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

#include <list>
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
	bool open;
	uint16_t sport;
	std::list<pkt> recvbuf;

	VirtualSocket() {
		reset(false);
	}

	void reset(bool open_) {
		open = open_;
		sport = 0;
		recvbuf.clear();
	}
};

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

static inline void maybe_init_socket_map() {
	if (socket_map.size() == 0) {
		int count = EMSOCKET_MAX_FD - EMSOCKET_BASE_FD;
		for (int idx = 0; idx < count; idx++) {
			socket_map.push_back(new VirtualSocket());
		}
	}
}

// Must be called holding the mutex
static VirtualSocket *getvs(int fd) {
	assert(fd >= EMSOCKET_BASE_FD && fd < EMSOCKET_MAX_FD);
	maybe_init_socket_map();
	int idx = fd - EMSOCKET_BASE_FD;
	auto vs = socket_map[idx];
	assert(vs && vs->open);
	return vs;
}

/**************************************************************************************************/

#define VLOCK()   const std::lock_guard<std::mutex> lock(mutex)

int emsocket_socket(int domain, int type, int protocol) {
	VLOCK();
	maybe_init_socket_map();
	int idx = 0;
        for (; idx < socket_map.size(); idx++) {
		if (!socket_map[idx]->open) {
			break;
		}
	}
	if (idx == socket_map.size()) {
		errno = EMFILE;
		return -1;
	}
	socket_map[idx]->reset(true);
	return EMSOCKET_BASE_FD + idx;
}

int emsocket_socketpair(int domain, int type, int protocol, int fds[2]);

int emsocket_bind(int fd, const struct sockaddr *addr, socklen_t len) {
	VLOCK();
	auto vs = getvs(fd);
	assert(vs->sport == 0);
	uint16_t port = get_port(addr, len);
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

int emsocket_getsockname(int fd, struct sockaddr *addr, socklen_t *len);

int emsocket_connect(int fd, const struct sockaddr *addr, socklen_t len);

int emsocket_getpeername(int fd, struct sockaddr *addr, socklen_t *len);

ssize_t emsocket_send(int fd, const void *buf, size_t n, int flags);

ssize_t emsocket_recv(int fd, void *buf, size_t n, int flags);

ssize_t emsocket_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len) {
	if (!is_localhost(addr, addr_len)) {
		// Sending to other than localhost not yet implemented
		return 0;
	}
	uint16_t source_port;
	uint16_t dest_port = get_port(addr, addr_len);
	VirtualSocket* dest_vs = nullptr;
	{
		VLOCK();
		source_port = getvs(fd)->sport;
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
		dest_vs->recvbuf.emplace_back(source_port, (const char*)buf, n);
	}
	dest_vs->cv.notify_all();
	return n;
}

ssize_t emsocket_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len) {
	VirtualSocket *vs;
	{
		VLOCK();
		vs = getvs(fd);
	}
	// For now, this should never be called in a blocking situation.
	assert(vs->recvbuf.size() > 0);
	const std::lock_guard<std::mutex> lock(vs->mutex);
	const pkt &p = vs->recvbuf.front();
	ssize_t written = std::min(p.data.size(), n);
	bool truncated = (written != (ssize_t)p.data.size());
	memcpy(buf, &p.data[0], written);
	if (addr) {
		struct sockaddr_in ai = {0};
		ai.sin_family = AF_INET;
		ai.sin_port = htons(p.source_port);
		ai.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		memcpy(addr, &ai, std::min((size_t)*addr_len, sizeof(ai)));
		*addr_len = sizeof(ai);
	}
	vs->recvbuf.pop_front();
	if (truncated) errno = EMSGSIZE;
	//std::cout << "sockfd=" << sockfd << " Received packet of size " << written << std::endl;
	return written;
}


ssize_t emsocket_sendmsg(int fd, const struct msghdr *message, int flags);

int emsocket_sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags);

ssize_t emsocket_recvmsg(int fd, struct msghdr *message, int flags);

int emsocket_recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags, struct timespec *tmo);

int emsocket_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);

int emsocket_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
	return -1;
}

int emsocket_listen(int fd, int n);

int emsocket_accept(int fd, struct sockaddr *addr, socklen_t *addr_len);

int emsocket_accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags);

int emsocket_shutdown(int fd, int how);

int emsocket_sockatmark(int fd);

int emsocket_isfdtype(int fd, int fdtype);

int emsocket_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

void emsocket_freeaddrinfo(struct addrinfo *res);

const char* emsocket_gai_strerror(int errcode);

struct hostent *emsocket_gethostbyname(const char *name);

struct hostent *emsocket_gethostbyaddr(const void *addr, socklen_t len, int type);

void emsocket_sethostent(int stayopen);

void emsocket_endhostent(void);

void emsocket_herror(const char *s);

const char *emsocket_hstrerror(int err);

struct hostent *emsocket_gethostent(void);

struct hostent *emsocket_gethostbyname2(const char *name, int af);

int emsocket_gethostent_r(struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);

int emsocket_gethostbyaddr_r(const void *addr, socklen_t len, int type, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);

int emsocket_gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);

int emsocket_gethostbyname2_r(const char *name, int af, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);

// Cheap hack
// Only supports select on a single fd
int emsocket_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	int sockfd = nfds - 1;
	assert(FD_ISSET(sockfd, readfds));
	VirtualSocket *vs;
	{
		VLOCK();
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

int emsocket_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

int emsocket_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int emsocket_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);

int emsocket_epoll_create(int);

int emsocket_epoll_create1(int);

int emsocket_epoll_ctl(int, int, int, struct epoll_event *);

int emsocket_epoll_wait(int, struct epoll_event *, int, int);

int emsocket_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);

int emsocket_close(int fd) {
	if (fd < EMSOCKET_BASE_FD) {
		return ::close(fd);
	}
	VLOCK();
	auto vs = getvs(fd);
	if (vs->sport) {
		port_map.erase(vs->sport);
		vs->sport = 0;
	}
	vs->reset(false);
	return 0;
}

int emsocket_fcntl(int fd, int cmd, ...) {
  abort();
}

int emsocket_ioctl(int fd, unsigned long request, ...) {
  abort();
}

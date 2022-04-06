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

#include <list>
#include <netinet/in.h>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <iomanip>
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

#include "VirtualSocket.h"

#include "emsocket.h"

using namespace emsocket;

#if EMSOCKET_DEBUG

std::mutex dbg_mutex;
#define DBG(x)   do { \
  const std::lock_guard<std::mutex> lock(dbg_mutex); \
  x \
} while(0)

#else

#define DBG(x)   do { } while (0)

#endif

/**************************************************************************************************/

int emsocket_socket(int domain, int type, int protocol) {
        DBG(std::cerr << "emsocket_socket " << domain << "," << type << "," << protocol << std::endl;);
	if (domain != AF_INET) {
		DBG(std::cerr << "emsocket_socket bad domain: " << domain << std::endl;);
		errno = EINVAL;
		return -1;
	}
	if (type != SOCK_STREAM && type != SOCK_DGRAM) {
		DBG(std::cerr << "emsocket_socket bad type: " << type << std::endl;);
		errno = EINVAL;
		return -1;
	}
	if (protocol == 0) {
            if (type == SOCK_STREAM) protocol = IPPROTO_TCP;
            if (type == SOCK_DGRAM) protocol = IPPROTO_UDP;
        }
        if (type == SOCK_DGRAM && protocol != IPPROTO_UDP) {
		DBG(std::cerr << "emsocket_socket bad dgram protocol: " << protocol << std::endl;);
		errno = EINVAL;
		return -1;
	}
        if (type == SOCK_STREAM && protocol != IPPROTO_TCP) {
		DBG(std::cerr << "emsocket_socket bad stream protocol: " << protocol << std::endl;);
		errno = EINVAL;
		return -1;
        }
        bool is_udp = (type == SOCK_DGRAM);
	auto vs = VirtualSocket::allocate(is_udp);
	if (!vs) {
		errno = EMFILE;
		return -1;
	}
        DBG(std::cerr << "emsocket_socket returns fd=" << vs->fd() << ", udp=" << vs->isUDP() << std::endl;);
	return vs->fd();
}

int emsocket_socketpair(int domain, int type, int protocol, int fds[2]);

int emsocket_bind(int fd, const struct sockaddr *addr, socklen_t len) {
	auto vs = VirtualSocket::get(fd);
	if (!vs->bind(SocketAddr(addr, len))) {
                DBG(std::cerr << "emsocket_bind failed" << std::endl;);
		errno = EADDRINUSE;
		return -1;
	}
        DBG(std::cerr << "emsocket_bind success fd=" << fd << " bindAddr=" << vs->getBindAddr() << std::endl;);
	return 0;
}

int emsocket_getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
        DBG(std::cerr << "emsocket_getsockname fd=" << fd << std::endl;);
	auto vs = VirtualSocket::get(fd);
	vs->getBindAddr().copyTo(addr, len);
        DBG(std::cerr << "    --> " << vs->getBindAddr() << std::endl;);
	return 0;
}

int emsocket_connect(int fd, const struct sockaddr *addr, socklen_t len) {
	SocketAddr dest(addr, len);
        DBG(std::cerr << "emsocket_connect: fd=" << fd << ", " << dest << std::endl;);
	auto vs = VirtualSocket::get(fd);
	if (vs->isUDP()) {
		// connect() on a UDP socket actually has a particular meaning...
		// but this is not implemented here.
                DBG(std::cerr << "emsocket_connect: Unexpected UDP" << std::endl;);
		errno = EPROTOTYPE;
		return -1;
	}
	if (vs->isConnected() || vs->isShutdown()) {
                DBG(std::cerr << "emsocket_connect: Already connected or shutdown" << std::endl;);
		errno = EISCONN;
		return -1;
	}
        if (!vs->startConnect(dest)) {
		DBG(std::cerr << "emsocket_connect: startConnect failed" << std::endl;);
		errno = ECONNREFUSED;
		return -1;
	}
        if (vs->isConnected() && !vs->isShutdown()) {
            return 0;
        }
        if (!vs->canBlock()) {
                DBG(std::cerr << "emsocket_connect: Connection in progress" << std::endl;);
		errno = EINPROGRESS;
		return -1;
        }
	vs->waitForConnect();
	if (!vs->isConnected() || vs->isShutdown()) {
                DBG(std::cerr << "emsocket_connect: Connection failed after wait" << std::endl;);
		errno = ECONNREFUSED;
		return -1;
	}
	return 0;
}

int emsocket_getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
    DBG(std::cerr << "emsocket_getpeername: fd=" << fd << std::endl;);
    auto vs = VirtualSocket::get(fd);
    if (!vs->isConnected()) {
        errno = ENOTCONN;
        return -1;
    }
    vs->getRemoteAddr().copyTo(addr, len);
    return 0;
}

ssize_t emsocket_send(int fd, const void *buf, size_t n, int flags) {
    DBG(std::cerr << "emsocket_send: fd=" << fd << ", n = " << n << std::endl;);
    auto vs = VirtualSocket::get(fd);
    if (!vs->isConnected() || vs->isShutdown()) {
        DBG(std::cerr << "   --> not connected" << std::endl;);
        errno = ENOTCONN;
	return -1;
    }
    flags &= ~MSG_NOSIGNAL; // no signals anyway
    if (flags != 0) {
        DBG(std::cerr << "Unsupported flags in emsocket_send: " << flags << std::endl;);
        errno = EOPNOTSUPP;
        return -1;
    }
    vs->write(buf, n);
    return n;
}

ssize_t emsocket_recv(int fd, void *buf, size_t n, int flags) {
    DBG(std::cerr << "emsocket_recv: fd=" << fd << ", n=" << n << std::endl;);
    auto vs = VirtualSocket::get(fd);
    if (flags != 0) {
        DBG(std::cerr << "Unsupported flags in emsocket_recv: " << flags << std::endl;);
        errno = EOPNOTSUPP;
        return -1;
    }
    // If there's data ready to go, give it back.
    ssize_t bytes = vs->read(buf, n);
    if (bytes > 0) {
        DBG(std::cerr << "    --> read " << bytes << std::endl;);
        return bytes;
    }
    if (!vs->isConnected() || vs->isShutdown()) {
        DBG(std::cerr << "    --> not connected or shutdown" << std::endl;);
        errno = ENOTCONN;
	return -1;
    }
    if (!vs->canBlock()) {
        DBG(std::cerr << "    --> would block" << std::endl;);
        errno = EWOULDBLOCK;
        return -1;
    }
    vs->waitForData();
    bytes = vs->read(buf, n);
    DBG(std::cerr << "    --> read " << bytes << std::endl;);
    return bytes;
}

ssize_t emsocket_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len) {
    DBG(std::cerr << "emsocket_sendto fd=" << fd << ", n=" << n << std::endl;);
    if (addr == NULL || addr_len < sizeof(sockaddr_in)) {
        DBG(std::cerr << "    --> EDESTADDRREQ" << std::endl;);
        errno = EDESTADDRREQ;
        return -1;
    }
    SocketAddr dest(addr, addr_len);
    auto vs = VirtualSocket::get(fd);
    if (flags != 0) {
        DBG(std::cerr << "    --> EOPNOTSUPP" << std::endl;);
        errno = EOPNOTSUPP;
        return -1;
    }
    if (!vs->isUDP()) {
        if (addr != NULL || addr_len != 0) {
            DBG(std::cerr << "    --> EISCONN" << std::endl;);
            errno = EISCONN;
            return -1;
        }
        DBG(std::cerr << "    --> forwarding to emsocket_send" << std::endl;);
        return emsocket_send(fd, buf, n, flags);
    }
    if (!vs->isBound()) {
        DBG(std::cerr << "    --> autobinding" << std::endl;);
        // Autobind to random port
        if (!vs->bind(SocketAddr())) {
            DBG(std::cerr << "    --> EADDRINUSE" << std::endl;);
            errno = EADDRINUSE;
            return -1;
        }
    }
    vs->sendto(buf, n, dest);
    DBG(std::cerr << "    --> sent" << std::endl;);
    return n;
}

ssize_t emsocket_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len) {
    DBG(std::cerr << "emsocket_recvfrom fd=" << fd << ", n = " << n << std::endl;);
    auto vs = VirtualSocket::get(fd);
    if (flags != 0) {
        DBG(std::cerr << "emsocket: unsupported flags in recvfrom" << std::endl;);
        errno = EOPNOTSUPP;
        return -1;
    }
    if (!vs->isUDP()) {
        DBG(std::cerr << "    --> forwarding to emsocket_recv" << std::endl;);
        vs->getRemoteAddr().copyTo(addr, addr_len);
        return emsocket_recv(fd, buf, n, 0);
    }
    // Common case: UDP
    SocketAddr dest;
    ssize_t bytes = vs->recvfrom(buf, n, &dest); // nonblock
    if (bytes > 0) {
        DBG(std::cerr << "    --> got " << bytes << " from " << dest << std::endl;);
        dest.copyTo(addr, addr_len);
        return bytes;
    }
    if (!vs->canBlock()) {
        DBG(std::cerr << "    --> EWOULDBLOCK" << std::endl;);
        errno = EWOULDBLOCK;
        return -1;
    }
    vs->waitForData();
    bytes = vs->recvfrom(buf, n, &dest);
    dest.copyTo(addr, addr_len);
    DBG(std::cerr << "    --> got " << bytes << " from " << dest << " after wait" << std::endl;);
    return bytes;
}

ssize_t emsocket_sendmsg(int fd, const struct msghdr *message, int flags);

int emsocket_sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags);

ssize_t emsocket_recvmsg(int fd, struct msghdr *message, int flags);

int emsocket_recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags, struct timespec *tmo);

int emsocket_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    std::cerr << "emsocket_getsockopt: level=" << level << ", optname=" << optname << std::endl;
    if (level == SOL_SOCKET) {
        if (optname == SO_ERROR) {
            if (optval && optlen && *optlen == sizeof(int)) {
                int *val = (int*)optval;
                auto vs = VirtualSocket::get(fd);
                if (!vs->isConnected() || vs->isShutdown()) {
                    *val = ECONNREFUSED;
                } else {
                    *val = 0;
                }
                return 0;
            } else {
                errno = EINVAL;
                return -1;
            }
        } else {
            errno = ENOPROTOOPT;
            return -1;
        }
    }
    errno = ENOPROTOOPT;
    return -1;
}

int emsocket_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    std::cerr << "emsocket_setsockopt: level=" << level << ", optname=" << optname << std::endl;
    return -1;
}

int emsocket_listen(int fd, int n) {
    abort();
}

int emsocket_accept(int fd, struct sockaddr *addr, socklen_t *addr_len) {
    abort();
}

int emsocket_accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags);

int emsocket_shutdown(int fd, int how);

int emsocket_sockatmark(int fd);

int emsocket_isfdtype(int fd, int fdtype);

int emsocket_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    DBG(std::cerr << "emsocket_getaddrinfo: node=" << (node ? node : "NULL") << ", service=" << (service ? service : "NULL") << std::endl;);
    if (service != NULL) {
        // Not supported.
        std::cerr << "emsocket_getaddrinfo: service field not supported" << std::endl;
        return EAI_SERVICE;
    }
    if (hints && hints->ai_family != AF_INET) {
        // Not supported
        std::cerr << "emsocket_getaddrinfo: only AF_INET supported" << std::endl;
        return EAI_FAIL;
    }
    if (hints && hints->ai_flags != 0) {
        // Not supported
        std::cerr << "emsocket_getaddrinfo: ai_flags not supported" << std::endl;
        return EAI_FAIL;
    }
    // Query the proxy
    int fd = emsocket_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "emsocket_getaddrinfo: emsocket_socket failed, errno = " << errno << std::endl;
        return EAI_SYSTEM;
    }
    SocketAddr dnsAddr("10.0.0.1", 53);
    std::cerr << "CONNECTING TO DNS=" << dnsAddr << std::endl;
    int rc = emsocket_connect(fd, dnsAddr.sockaddr_ptr(), dnsAddr.sockaddr_len());
    if (rc != 0) {
        std::cerr << "emsocket_getaddrinfo: emsocket_connect failed, errno = " << errno << std::endl;
        emsocket_close(fd);
        return EAI_SYSTEM;
    }
    size_t nodeLen = strlen(node);
    if (emsocket_send(fd, node, nodeLen, 0) != nodeLen) {
        std::cerr << "emsocket_getaddrinfo: emsocket_send failed, errno = " << errno << std::endl;
        return EAI_SYSTEM;
    }
    uint32_t addr;
    if (emsocket_read(fd, &addr, 4) != 4) {
        std::cerr << "emsocket_getaddrinfo: emsocket_read failed, errno = " << errno << std::endl;
        return EAI_SYSTEM;
    }
    if (addr == 0) {
        return EAI_FAIL;
    }
    if (emsocket_close(fd) != 0) {
        std::cerr << "emsocket_getaddrinfo: emsocket_close failed, errno = " << errno << std::endl;
        return EAI_SYSTEM;
    }
    struct addrinfo *result = (struct addrinfo*)malloc(sizeof(struct addrinfo));
    memset(result, 0, sizeof(struct addrinfo));
    result->ai_family = AF_INET;
    result->ai_socktype = hints ? hints->ai_socktype : 0;
    result->ai_protocol = hints ? hints->ai_protocol : 0;
    result->ai_addrlen = sizeof(sockaddr_in);

    struct sockaddr_in* sin = (struct sockaddr_in*)malloc(sizeof(sockaddr_in));
    memset(sin, 0, sizeof(sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;

    result->ai_addr = (struct sockaddr*)sin;
    *res = result;
    return 0;
}

void emsocket_freeaddrinfo(struct addrinfo *res) {
    if (res) {
        free(res->ai_addr);
        free(res);
    }
    return;
}

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

#define MAX_SELECT_FDS   64

static void print_fd_set(int nfds, fd_set *x) {
    if (x == NULL) {
        std::cerr << "NULL";
    } else {
        std::cerr << "[ ";
        for (int fd = 0; fd < nfds; fd++) {
            if (FD_ISSET(fd, x)) {
                std::cerr << fd << " ";
            }
        }
        std::cerr << "]";
    }
}

int emsocket_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
#if EMSOCKET_DEBUG
    DBG(
        std::cerr << "emsocket_select nfds=" << nfds;
        std::cerr << ", readfds="; print_fd_set(nfds, readfds);
        std::cerr << ", writefs="; print_fd_set(nfds, writefds);
        std::cerr << ", exceptfds="; print_fd_set(nfds, exceptfds);
        std::cerr << ", timeout=";
        if (timeout) {
            std::cerr << timeout->tv_sec << "s " << timeout->tv_usec << "us";
        } else {
            std::cerr << "NULL";
        }
        std::cerr << std::endl;
    );
#endif
    // Convert to a call to poll() instead
    struct pollfd fds[MAX_SELECT_FDS] = { 0 };
    nfds_t count = 0;
    for (int fd = 0; fd < nfds; fd++) {
        bool check_read = readfds && FD_ISSET(fd, readfds);
        bool check_write = writefds && FD_ISSET(fd, writefds);
        bool check_except = exceptfds && FD_ISSET(fd, exceptfds);
        if (check_read || check_write || check_except) {
            if (count == MAX_SELECT_FDS) {
                DBG(std::cerr << "emsocket select() called with too many fds" << std::endl;);
                errno = EINVAL;
                return -1;
            }
            fds[count].fd = fd;
            fds[count].events = (check_read ? POLLIN : 0) | (check_write ? POLLOUT : 0);
            count++;
        }
    }
    if (readfds) FD_ZERO(readfds);
    if (writefds) FD_ZERO(writefds);
    if (exceptfds) FD_ZERO(exceptfds);
    int poll_timeout = -1;
    if (timeout) {
        poll_timeout = (timeout->tv_sec * 1000) + (timeout->tv_usec / 1000);
    }
    int ret = emsocket_poll(fds, count, poll_timeout);
    if (ret <= 0) {
        //DBG(std::cerr << "    --> returning " << ret << std::endl;);
        return ret;
    }

    int bitcount = 0;
    for (int i = 0; i < count; i++) {
        int fd = fds[i].fd;
        short revents = fds[i].revents;
        if (readfds && (revents & (POLLIN|POLLHUP))) {
            bitcount++;
            FD_SET(fd, readfds);
        }
        if (writefds && (revents & POLLOUT)) {
            bitcount++;
            FD_SET(fd, writefds);
        }
        if (exceptfds && (revents & (POLLERR|POLLHUP))) {
            bitcount++;
            FD_SET(fd, exceptfds);
        }
    }
#if EMSOCKET_DEBUG
    DBG(
        std::cerr << "    --> returning " << bitcount;
        std::cerr << ", readfds="; print_fd_set(nfds, readfds);
        std::cerr << ", writefs="; print_fd_set(nfds, writefds);
        std::cerr << ", exceptfds="; print_fd_set(nfds, exceptfds);
        std::cerr << std::endl;
    );
#endif
    return bitcount;
}

int emsocket_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

#define MAX_POLL_FDS 64

int emsocket_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    int count = 0;
    std::function<bool(void)> predicate = [&]() {
        count = 0;
        for (int i = 0; i < nfds; i++) {
            if (fds[i].fd < 0) continue;
            auto vs = VirtualSocket::get(fds[i].fd);
            short revents = 0;
            if (fds[i].events & POLLIN) {
                if (vs->hasData()) {
                    revents |= POLLIN;
                }
                if (vs->isShutdown()) {
                    revents |= POLLIN | POLLHUP;
                }
            }
            if (fds[i].events & POLLOUT) {
                if (vs->isUDP() || vs->isConnected() || vs->isShutdown()) {
                    revents |= POLLOUT;
                }
            }
            fds[i].revents = revents;
            if (revents) {
                count += 1;
            }
        }
        // Keep waiting until count > 0
        return (count > 0);
    };
    //if (emscripten_is_main_browser_thread()) {
    //    //DBG(std::cerr << "emsocket_poll fast exit due to being on main thread" << std::endl;);
    //    VirtualSocket::runWithLock(predicate);
    //    return count;
    //}
    VirtualSocket::waitFor(predicate, timeout);
    return count;
}

int emsocket_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);

int emsocket_epoll_create(int);

int emsocket_epoll_create1(int);

int emsocket_epoll_ctl(int, int, int, struct epoll_event *);

int emsocket_epoll_wait(int, struct epoll_event *, int, int);

int emsocket_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);

ssize_t emsocket_read(int fd, void *buf, size_t count) {
    if (fd < EMSOCKET_BASE_FD) return read(fd, buf, count);
    return emsocket_recv(fd, buf, count, 0);
}

ssize_t emsocket_write(int fd, const void *buf, size_t count) {
    if (fd < EMSOCKET_BASE_FD) return write(fd, buf, count);
    return emsocket_send(fd, buf, count, 0);
}

int emsocket_close(int fd) {
	if (fd < EMSOCKET_BASE_FD) {
		return ::close(fd);
	}
	auto vs = VirtualSocket::get(fd);
	vs->close();
	return 0;
}

int emsocket_fcntl(int fd, int cmd, ...) {
    auto vs = VirtualSocket::get(fd);
    if (cmd == F_GETFL) {
        return vs->isBlocking() ? O_NONBLOCK : 0;
    } else if (cmd == F_SETFL) {
        va_list ap;
        va_start(ap, cmd);
        int flags = va_arg(ap, int);
        vs->setBlocking((flags & O_NONBLOCK) ? false : true);
        flags &= ~O_NONBLOCK;
        if (flags) {
            std::cerr << "emsocket_fcntl unrecognized flags=" << flags << std::endl;
        }
        va_end(ap);
        return 0;
    }
    std::cerr << "emsocket_fcntl unknown fcntl cmd=" << cmd << std::endl;
    return -1;
}

int emsocket_ioctl(int fd, unsigned long request, ...) {
  std::cerr << "emsocket_ioctl not implemented, request=" << request << std::endl;
  abort();
}

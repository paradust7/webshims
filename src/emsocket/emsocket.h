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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// No idea what this is (it appears emscripten or musl specific)
// but it redeclares ioctl(), so it needs to be here.
#include <stropts.h>

#include <emscripten/threading.h>

// This must match the same defines in VirtualSocket.h
#define EMSOCKET_BASE_FD   512
#define EMSOCKET_MAX_FD    1024

#ifdef __cplusplus
extern "C" {
#endif

struct mmsghdr;

/* From sys/socket.h */

extern int emsocket_socket(int domain, int type, int protocol);
extern int emsocket_socketpair(int domain, int type, int protocol, int fds[2]);
extern int emsocket_bind(int fd, const struct sockaddr *addr, socklen_t len);
extern int emsocket_getsockname(int fd, struct sockaddr *addr, socklen_t *len);
extern int emsocket_connect(int fd, const struct sockaddr *addr, socklen_t len);
extern int emsocket_getpeername(int fd, struct sockaddr *addr, socklen_t *len);
extern ssize_t emsocket_send(int fd, const void *buf, size_t n, int flags);
extern ssize_t emsocket_recv(int fd, void *buf, size_t n, int flags);
extern ssize_t emsocket_sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len);
extern ssize_t emsocket_recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len);
extern ssize_t emsocket_sendmsg(int fd, const struct msghdr *message, int flags);
/* GNU extension */
extern int emsocket_sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags);
extern ssize_t emsocket_recvmsg(int fd, struct msghdr *message, int flags);
/* GNU extension */
extern int emsocket_recvmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags, struct timespec *tmo);
extern int emsocket_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
extern int emsocket_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
extern int emsocket_listen(int fd, int n);
extern int emsocket_accept(int fd, struct sockaddr *addr, socklen_t *addr_len);
/* GNU extension */
extern int emsocket_accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags);
extern int emsocket_shutdown(int fd, int how);
extern int emsocket_sockatmark(int fd);
extern int emsocket_isfdtype(int fd, int fdtype);

/* From netdb.h */

extern int emsocket_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
extern void emsocket_freeaddrinfo(struct addrinfo *res);

extern struct hostent *emsocket_gethostbyname(const char *name);
extern struct hostent *emsocket_gethostbyaddr(const void *addr, socklen_t len, int type);

extern void emsocket_sethostent(int stayopen);
extern void emsocket_endhostent(void);

extern void emsocket_herror(const char *s);
extern const char *emsocket_hstrerror(int err);

/* System V/POSIX extension */
extern struct hostent *emsocket_gethostent(void);

/* GNU extensions */
extern struct hostent *emsocket_gethostbyname2(const char *name, int af);
extern int emsocket_gethostent_r(struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
extern int emsocket_gethostbyaddr_r(const void *addr, socklen_t len, int type, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
extern int emsocket_gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);
extern int emsocket_gethostbyname2_r(const char *name, int af, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop);

/* From sys/select.h */
extern int emsocket_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
extern int emsocket_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

/* From poll.h */

extern int emsocket_poll(struct pollfd *fds, nfds_t nfds, int timeout);
/* GNU extension */
extern int emsocket_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);

/* From sys/epoll.h */

extern int emsocket_epoll_create(int);
extern int emsocket_epoll_create1(int);
extern int emsocket_epoll_ctl(int, int, int, struct epoll_event *);
extern int emsocket_epoll_wait(int, struct epoll_event *, int, int);
extern int emsocket_epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);

/* From unistd.h */
extern ssize_t emsocket_read(int fd, void *buf, size_t count);
extern ssize_t emsocket_write(int fd, const void *buf, size_t count);
extern int emsocket_close(int fd);

/* From fcntl.h */
extern int emsocket_fcntl(int fd, int cmd, ...);

/* From sys/ioctl.h */
extern int emsocket_ioctl(int fd, unsigned long request, ...);

#ifdef __cplusplus
} // extern "C"
#endif

#ifndef EMSOCKET_INTERNAL
#define socket                  emsocket_socket
#define socketpair              emsocket_socketpair
#define bind                    emsocket_bind
#define getsockname             emsocket_getsockname
#define connect                 emsocket_connect
#define getpeername             emsocket_getpeername
#define send                    emsocket_send
#define recv                    emsocket_recv
#define sendto                  emsocket_sendto
#define recvfrom                emsocket_recvfrom
#define sendmsg                 emsocket_sendmsg
#define sendmmsg                emsocket_sendmmsg
#define recvmsg                 emsocket_recvmsg
#define recvmmsg                emsocket_recvmmsg
#define getsockopt              emsocket_getsockopt
#define setsockopt              emsocket_setsockopt
#define listen                  emsocket_listen
#define accept                  emsocket_accept
#define accept4                 emsocket_accept4
#define shutdown                emsocket_shutdown
#define sockatmark              emsocket_sockatmark
#define isfdtype                emsocket_isfdtype
#define getaddrinfo             emsocket_getaddrinfo
#define freeaddrinfo            emsocket_freeaddrinfo
#define gethostbyname           emsocket_gethostbyname
#define gethostbyaddr           emsocket_gethostbyaddr
#define sethostent              emsocket_sethostent
#define endhostent              emsocket_endhostent
#define herror                  emsocket_herror
#define hstrerror               emsocket_hstrerror
#define gethostent              emsocket_gethostent
#define gethostbyname2          emsocket_gethostbyname2
#define gethostent_r            emsocket_gethostent_r
#define gethostbyaddr_r         emsocket_gethostbyaddr_r
#define gethostbyname_r         emsocket_gethostbyname_r
#define gethostbyname2_r        emsocket_gethostbyname2_r
#define select                  emsocket_select
#define pselect                 emsocket_pselect
#define poll                    emsocket_poll
#define ppoll                   emsocket_ppoll
#define epoll_create            emsocket_epoll_create
#define epoll_create1           emsocket_epoll_create1
#define epoll_ctl               emsocket_epoll_ctl
#define epoll_wait              emsocket_epoll_wait
#define epoll_pwait             emsocket_epoll_pwait
#define read                    emsocket_read
#define write                   emsocket_write
#define close                   emsocket_close

// Special macros needed to handle __VA_ARGS__ forwarding

#define fcntl(_fd, ...) ({ \
  int __fcntl_fd = (_fd); \
  int __fcntl_rc; \
  if (__fcntl_fd < EMSOCKET_BASE_FD) { \
    __fcntl_rc = fcntl(__fcntl_fd, __VA_ARGS__); \
  } else { \
    __fcntl_rc = emsocket_fcntl(__fcntl_fd, __VA_ARGS__); \
  } \
  __fcntl_rc; \
})


#define ioctl(_fd, ...) ({ \
  int __ioctl_fd = (_fd); \
  int __ioctl_rc; \
  if (__ioctl_fd < EMSOCKET_BASE_FD) { \
    __ioctl_rc = ioctl(__ioctl_fd, __VA_ARGS__); \
  } else { \
    __ioctl_rc = emsocket_ioctl(__ioctl_fd, __VA_ARGS__); \
  } \
  __ioctl_rc; \
})

#endif

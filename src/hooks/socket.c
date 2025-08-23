#include <stdbool.h>
#include <dlfcn.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "hooks/socket.h"
#include "generic/protocol.h"
#include "hooks/printbuf.h"

static bool hooked = true;

// int connect(int fd, const struct sockaddr *addr, socklen_t len)
// {
//     int (*real_connect)(int fd, const struct sockaddr* addr, socklen_t len) = dlsym(RTLD_NEXT, "connect");
//     fprintf(stderr, "CALL TO connect\n");
//     return real_connect(fd, addr, len);
// }

// int bind(int fd, const struct sockaddr *addr, socklen_t len)
// {
//     int (*real_bind)(int fd, const struct sockaddr* addr, socklen_t len) = dlsym(RTLD_NEXT, "bind");
//     fprintf(stderr, "CALL TO bind\n");
//     return real_bind(fd, addr, len);
// }

// ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
// {
//     // printf("SENDMSG\n");
//     // ssize_t (*real_sendmsg)(int fd, const struct msghdr *message, int flags) = dlsym(RTLD_NEXT, "sendmsg");
//     typeof(&sendmsg) real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     char msgname[INET6_ADDRSTRLEN] = {0};

//     struct msghdr message_copy = *message;

//     if (!hooked)
//     {
//         return real_sendmsg(fd, message, flags);
//     }

//     if (message_copy.msg_name == NULL)
//     {
//         message_copy.msg_name = msgname;
//         message_copy.msg_namelen = INET6_ADDRSTRLEN;
//     }

//     rc = real_sendmsg(fd, message, flags);
//     // fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);

//     // if (socket_type == SOCK_STREAM)
//     // {
//     //     fprintf(stderr, "CALL TO sendmsg\n");
//     //     fprintf(stderr, "%d -> %d\n", sa_local.sin6_port, sa_remote.sin6_port);

//     // }

//     // fwrite(message->msg_iov->iov_base, message->msg_iovlen, 1, stdout);

//     // printbuf(message->msg_iov->iov_base, message->msg_iovlen, 80, 80, false);
    
//     // if (socket_type == SOCK_STREAM)
//     // {
//     //     inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     // }
//     // else
//     // {
//     //     struct sockaddr_in* dgram_remote = message_copy.msg_name;
//     //     struct sockaddr_in6* dgram_remote6 = message_copy.msg_name;
//     //     fprintf(stderr, "DGRAM remote = %p\n", message_copy.msg_name);
//     //     if (dgram_remote->sin_family == AF_INET6)
//     //     {
//     //         inet_ntop(dgram_remote->sin_family, &(dgram_remote6->sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     }
//     //     else
//     //     {
//     //         inet_ntop(dgram_remote->sin_family, &(dgram_remote->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     }
//     // }

//     // fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     // fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

// ssize_t recvmsg(int fd, struct msghdr *message, int flags)
// {
//     // printf("RECVMSG\n");
//     // ssize_t (*real_recvmsg)(int fd, struct msghdr *message, int flags) = dlsym(RTLD_NEXT, "recvmsg");
//     typeof(&recvmsg) real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     char buf[INET6_ADDRSTRLEN] = {0};

//     if (!hooked)
//     {
//         return real_recvmsg(fd, message, flags);
//     }

//     if (message->msg_name == NULL)
//     {
//         message->msg_name = buf;
//         message->msg_namelen = INET6_ADDRSTRLEN;
//     }

//     rc = real_recvmsg(fd, message, flags);
//     // fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);
//     // if (socket_type == SOCK_STREAM)
//     // {
//     //     fprintf(stderr, "CALL TO recvmsg\n");
//     // }
//     // if (socket_type == SOCK_STREAM)
//     // {
//     //     inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     // }
//     // else
//     // {
//     //     struct sockaddr_in* dgram_remote = message->msg_name;
//     //     struct sockaddr_in6* dgram_remote6 = message->msg_name;
//     //     fprintf(stderr, "DGRAM remote = %p\n", message->msg_name);
//     //     if (dgram_remote->sin_family == AF_INET6)
//     //     {
//     //         inet_ntop(dgram_remote->sin_family, &(dgram_remote6->sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     }
//     //     else
//     //     {
//     //         inet_ntop(dgram_remote->sin_family, &(dgram_remote->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//     //     }
//     // }
//     // fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     // fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

// ssize_t send(int fd, const void* buf, size_t n, int flags)
// {
//     printf("SEND\n");
//     // ssize_t (*real_send)(int fd, const void* buf, size_t n, int flags) = dlsym(RTLD_NEXT, "send");
//     typeof(&send) real_send = dlsym(RTLD_NEXT, "send");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     struct sockaddr_in* sa_remote4 = (struct sockaddr_in*) &sa_remote;
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     struct sockaddr_in* sa_local4 = (struct sockaddr_in*) &sa_local;
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     if (!hooked)
//     {
//         return real_send(fd, buf, n, flags);
//     }

    
//     // fprintf(stderr, "CALL TO send, ");
//     rc = real_send(fd, buf, n, flags);
//     // printbuf(buf, rc, 80, 80, true);
//     // fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);
//     if (sa_remote.sin6_family == AF_INET6)
//     {
//         inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     else if (sa_remote.sin6_family == AF_INET)
//     {
//         inet_ntop(sa_remote4->sin_family, &(sa_remote4->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local4->sin_family, &(sa_local4->sin_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     // fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     // fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

// ssize_t recv(int fd, void* buf, size_t n, int flags)
// {
//     printf("RECV\n");
//     // ssize_t (*real_recv)(int fd, void* buf, size_t n, int flags) = dlsym(RTLD_NEXT, "recv");
//     typeof(&recv) real_recv = dlsym(RTLD_NEXT, "recv");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     struct sockaddr_in* sa_remote4 = (struct sockaddr_in*) &sa_remote;
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     struct sockaddr_in* sa_local4 = (struct sockaddr_in*) &sa_local;
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     if (!hooked)
//     {
//         return real_recv(fd, buf, n, flags);
//     }

    
//     rc = real_recv(fd, buf, n, flags);

//     // printbuf(buf, rc, 80, 80, true);
//     // fprintf(stderr, "CALL TO recv, ");
//     // fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);
//     if (sa_remote.sin6_family == AF_INET6)
//     {
//         inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     else if (sa_remote.sin6_family == AF_INET)
//     {
//         inet_ntop(sa_remote4->sin_family, &(sa_remote4->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local4->sin_family, &(sa_local4->sin_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     // fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     // fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

// ssize_t sendto(int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len)
// {
//     printf("SENDTO\n");
//     // ssize_t (*real_sendto)(int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len) = dlsym(RTLD_NEXT, "send");
//     typeof(&sendto) real_sendto = dlsym(RTLD_NEXT, "send");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     struct sockaddr_in* sa_remote4 = (struct sockaddr_in*) &sa_remote;
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     struct sockaddr_in* sa_local4 = (struct sockaddr_in*) &sa_local;
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     if (!hooked)
//     {
//         return real_sendto(fd, buf, n, flags, addr, addr_len);
//     }

//     fprintf(stderr, "CALL TO sendto, ");
//     rc = real_sendto(fd, buf, n, flags, addr, addr_len);
//     fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);
//     if (sa_remote.sin6_family == AF_INET6)
//     {
//         inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     else if (sa_remote.sin6_family == AF_INET)
//     {
//         inet_ntop(sa_remote4->sin_family, &(sa_remote4->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local4->sin_family, &(sa_local4->sin_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

// ssize_t recvfrom(int fd, void *__restrict buf, size_t n, int flags, struct sockaddr *__restrict addr, socklen_t *__restrict addr_len)
// {
//     printf("RECVFROM\n");
//     // ssize_t (*real_recvfrom)(int fd, void* buf, size_t n, int flags, struct sockaddr* addr, socklen_t* addr_len) = dlsym(RTLD_NEXT, "recv");
//     typeof(&recvfrom) real_recvfrom = dlsym(RTLD_NEXT, "recv");

//     ssize_t rc;

//     struct sockaddr_in6 sa_remote = {0};
//     struct sockaddr_in* sa_remote4 = (struct sockaddr_in*) &sa_remote;
//     socklen_t len_remote = sizeof(sa_remote);
//     char addr_remote[INET6_ADDRSTRLEN] = {0};

//     struct sockaddr_in6 sa_local = {0};
//     struct sockaddr_in* sa_local4 = (struct sockaddr_in*) &sa_local;
//     socklen_t len_local = sizeof(sa_local);
//     char addr_local[INET6_ADDRSTRLEN] = {0};

//     int socket_type;
//     int socket_type_length = sizeof(int);

//     if (!hooked)
//     {
//         return real_recvfrom(fd, buf, n, flags, addr, addr_len);
//     }

//     rc = real_recvfrom(fd, buf, n, flags, addr, addr_len);
//     fprintf(stderr, "CALL TO recvfrom, ");
//     fprintf(stderr, "LENGTH is %ld\n", rc);
//     getpeername(fd, (struct sockaddr*) &sa_remote, &len_remote);
//     getsockname(fd, (struct sockaddr*) &sa_local, &len_local);
//     getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &socket_type_length);
//     if (sa_remote.sin6_family == AF_INET6)
//     {
//         inet_ntop(sa_remote.sin6_family, &(sa_remote.sin6_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local.sin6_family, &(sa_local.sin6_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     else if (sa_remote.sin6_family == AF_INET)
//     {
//         inet_ntop(sa_remote4->sin_family, &(sa_remote4->sin_addr), addr_remote, INET6_ADDRSTRLEN);
//         inet_ntop(sa_local4->sin_family, &(sa_local4->sin_addr), addr_local, INET6_ADDRSTRLEN);
//     }
//     fprintf(stderr, "REMOTE : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_remote, be16toh(sa_remote.sin6_port), socket_type, len_remote);
//     fprintf(stderr, "LOCAL : FD = %d, IP = %s, PORT = %u, TYPE = %u, LEN = %u\n", fd, addr_local, be16toh(sa_local.sin6_port), socket_type, len_local);
//     return rc;
// }

void socket_set_hooked(bool b)
{
    hooked = b;
}

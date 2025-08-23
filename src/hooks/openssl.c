#include "hooks/printbuf.h"

#include <dlfcn.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>

int SSL_write(SSL *ssl, const void *buf, int num)
{
    // int fd = get_fd_from_ssl(ssl);
    // fprintf(stderr, "FD is %d\n", fd);
    typeof(&SSL_write) real_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    int rc = real_SSL_write(ssl, buf, num);
    void* buf_copy = malloc((unsigned int) num * sizeof(uint8_t));
    if (buf_copy != NULL)
    {
        memcpy(buf_copy, buf, (unsigned int) num * sizeof(uint8_t));
        printbuf(buf_copy, rc, 80, 80, true);
        free(buf_copy);
    }
    return rc;
}

int SSL_read(SSL *ssl, void *buf, int num)
{
    // int fd = get_fd_from_ssl(ssl);
    // fprintf(stderr, "FD is %d\n", fd);
    typeof(&SSL_read) real_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    int rc = real_SSL_read(ssl, buf, num);
    printbuf(buf, rc, 80, 80, true);
    return rc;
}

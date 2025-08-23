#include <dlfcn.h>
#include <quiche.h>

#include "hooks/printbuf.h"

ssize_t quiche_conn_recv(quiche_conn *conn, uint8_t *buf, size_t buf_len, const quiche_recv_info *info)
{
    typeof(&quiche_conn_recv) real_quiche_conn_recv = dlsym(RTLD_NEXT, "quiche_conn_recv");
    // printf("HOLE\n");
    ssize_t rc = real_quiche_conn_recv(conn, buf, buf_len, info);
    printbuf(buf, (ssize_t) buf_len, 443, 443, false);
    return rc;
}

// ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len, quiche_send_info *out_info)
// {
//     typeof(&quiche_conn_send) real_quiche_conn_send = dlsym(RTLD_NEXT, "quiche_conn_send");
//     printf("HOEL\n");
//     ssize_t rc = real_quiche_conn_send(conn, out, out_len, out_info);
//     printbuf(out, rc, 443, 443, false);
//     return rc;
// }

// ssize_t quiche_conn_send(quiche_conn *conn, uint8_t *out, size_t out_len, quiche_send_info *out_info)
// {
//     ssize_t rc;
//     typeof(&quiche_conn_send) real_quiche_conn_send = dlsym(RTLD_NEXT, "quiche_conn_send");
//     printf("HOEL\n");
//     uint8_t* newb = malloc(out_len * sizeof(uint8_t));
//     if (newb != NULL)
//     {
//         memcpy(newb, out, out_len * sizeof(uint8_t));
//     }
//     rc = real_quiche_conn_send(conn, out, out_len, out_info);
//     printf("BEFORE / AFTER SEND = %d\n", memcmp(newb, out, out_len * sizeof(uint8_t)));
//     if (newb != NULL)
//     {
//         printbuf(newb, out_len, 443, 443, false);
//         free(newb);
//     }
//     // printbuf(out, rc, 443, 443, false);
//     return rc;
// }

// ssize_t quiche_conn_stream_recv(quiche_conn *conn, uint64_t stream_id, uint8_t *out, size_t buf_len, bool *fin, uint64_t *out_error_code)
// {
//     typeof(&quiche_conn_stream_recv) real_quiche_conn_stream_recv = dlsym(RTLD_NEXT, "quiche_conn_stream_recv");
//     printf("LEOH\n");
//     ssize_t rc = real_quiche_conn_stream_recv(conn, stream_id, out, buf_len, fin, out_error_code);
//     printbuf(out, rc, 443, 443, false);
//     return rc;
// }

// ssize_t quiche_h3_recv_body(quiche_h3_conn *conn, quiche_conn *quic_conn, uint64_t stream_id, uint8_t *out, size_t out_len)
// {
//     typeof(&quiche_h3_recv_body) real_quiche_h3_recv_body = dlsym(RTLD_NEXT, "quiche_h3_recv_body");
//     printf("ELOH\n");
//     ssize_t rc = real_quiche_h3_recv_body(conn, quic_conn, stream_id, out, out_len);
//     printbuf(out, rc, 443, 443, false);
//     return rc;
// }

// ssize_t quiche_h3_send_body(quiche_h3_conn *conn, quiche_conn *quic_conn, uint64_t stream_id, const uint8_t *body, size_t body_len, bool fin)
// {
//     typeof(&quiche_h3_send_body) real_quiche_h3_send_body = dlsym(RTLD_NEXT, "quiche_h3_send_body");
//     printf("ELHO\n");
//     ssize_t rc = real_quiche_h3_send_body(conn, quic_conn, stream_id, body, body_len, fin);
//     printbuf(body, rc, 443, 443, false);
//     return rc;
// }

// ssize_t quiche_h3_send_request(quiche_h3_conn *conn, quiche_conn *quic_conn, const quiche_h3_header *headers, size_t headers_len, bool fin)
// {
//     typeof(&quiche_h3_send_request) real_quiche_h3_send_request = dlsym(RTLD_NEXT, "quiche_h3_send_request");
//     printf("LEHO\n");
//     ssize_t rc = real_quiche_h3_send_request(conn, quic_conn, headers, headers_len, fin);
//     printbuf(headers, headers_len, 443, 443, false);
//     return rc;
// }

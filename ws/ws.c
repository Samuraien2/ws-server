#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#define TEENY_SHA1_IMPLEMENTATION
#define B64_IMPLEMENTATION
#include "ws.h"
#include "b64.h"
#include "teenysha1.h"

#define WS_ACCEPT_LEN (b64_encode_out_len(sizeof(digest8_t)) + 1)

int get_header_value(const char *req, const char *header_name,
                     char *out, int out_size)
{
    const char *p = strcasestr(req, header_name); // case-insensitive search
    if (!p)
        return 0;

    p += strlen(header_name); // move past the header name

    // Skip spaces or tabs
    while (*p == ' ' || *p == '\t' || *p == ':')
        p++;

    // Copy until end of line
    int i = 0;
    while (*p != '\r' && *p != '\n' && *p != '\0' && i < out_size - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

WsState *ws_listen(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return NULL;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return NULL;
    }

    if (listen(fd, 10) < 0) {
        return NULL;
    }

    WsState *ws = malloc(sizeof(WsState));
    ws->fd = fd;
    return ws;
}

int read_http_header(int fd, char *buffer, int max_len) {
    int total = 0;

    while (total < max_len - 1) {
        int n = read(fd, buffer + total, max_len - 1 - total);
        if (n <= 0) {
            return -1;
        }
        total += n;
        buffer[total] = '\0';

        if (strstr(buffer, "\r\n\r\n")) {
            return total;
        }
    }

    return -1;
}

bool ws_handshake(int fd) {
    char req[2048];
    int header_len = read_http_header(fd, req, sizeof(req));

    if (header_len < 0) {
        return false;
    }

    char client_key[128];
    if (!get_header_value(req, "Sec-WebSocket-Key", client_key, sizeof(client_key))) {
        return false;
    }

    char src[256];
    unsigned char sha1_out[20];
    int srclen = snprintf(src, sizeof(src), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);

    SHA1 sha1 = {0};
    sha1_reset(&sha1);
    sha1_process_bytes(&sha1, src, srclen);
    digest8_t digest;
    sha1_get_digest_bytes(&sha1, digest);

    char sec_ws_accept[WS_ACCEPT_LEN];
    b64_encode((void*)digest, sizeof(digest), sec_ws_accept, WS_ACCEPT_LEN, B64_STD_ALPHA, B64_DEFAULT_PAD);
    sec_ws_accept[WS_ACCEPT_LEN-1] = '\0';

    dprintf(fd,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        sec_ws_accept
    );
    return true;
}

typedef struct {
    int fd;
    WsCallback cb;
} client_args_t;

void send_close(int fd, uint16_t code) {
    uint8_t buf[4] = {0x88, 0x02, code >> 8, code & 0xFF};
    write(fd, buf, sizeof(buf));
}

bool ws_read_frame(int fd, WsFrame *frame) {
    uint8_t hdr[2];
    if (read(fd, hdr, 2) != 2) return false;

    frame->fin = (hdr[0] & 0x80) != 0;
    frame->opcode = hdr[0] & 0x0F;
    uint8_t mask = (hdr[1] & 0x80) != 0;
    uint64_t len = hdr[1] & 0x7F;

    if (!mask) {
        return false;
    }

    if (len == 126) {
        uint8_t ext[2];
        if (read(fd, ext, 2) != 2) return false;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        if (read(fd, ext, 8) != 8) return false;
        len =
            ((uint64_t)ext[0] << 56) |
            ((uint64_t)ext[1] << 48) |
            ((uint64_t)ext[2] << 40) |
            ((uint64_t)ext[3] << 32) |
            ((uint64_t)ext[4] << 24) |
            ((uint64_t)ext[5] << 16) |
            ((uint64_t)ext[6] << 8) |
            ((uint64_t)ext[7]);
    }

    uint8_t mask_key[4];
    if (read(fd, mask_key, 4) != 4) return false;

    uint8_t *data = malloc(len);
    if (!data) return false;
    size_t read_total = 0;
    while (read_total < len) {
        ssize_t n = read(fd, data + read_total, len - read_total);
        if (n <= 0) {
            free(data);
            return false;
        }
        read_total += n;
    }

    // Unmask payload
    for (uint64_t i = 0; i < len; i++) {
        data[i] ^= mask_key[i % 4];
    }

    frame->payload_len = len;
    frame->payload = data;

    return true;
}

void *client_thread(void *arg) {
    client_args_t *args = (client_args_t*)arg;
    int fd = args->fd;
    WsCallback cb = args->cb;
    free(arg);

    if (!ws_handshake(fd)) {
        close(fd);
        return NULL;
    }

    cb(&(WsEvent){.conn = {
        .type = WS_EVENT_CONNECT,
        .user_id = fd,
    }});

    while (1) {
        WsFrame frame;
        if (!ws_read_frame(fd, &frame)) break;
        if (frame.opcode == 0x8) {
            send_close(fd, 1000);
            free(frame.payload);
            break;
        }

        cb(&(WsEvent){.msg = {
            .type = WS_EVENT_BINARY_MESSAGE,
            .user_id = fd,
            .bytes = frame.payload,
            .len = frame.payload_len
        }});

        free(frame.payload);
    }

    cb(&(WsEvent){.conn = {
        .type = WS_EVENT_DISCONNECT,
        .user_id = fd
    }});

    close(fd);
    return NULL;
}

bool ws_loop(WsState *ws, WsCallback event_callback) {
    socklen_t addrlen = sizeof(struct sockaddr_in);
    while (1) {
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(ws->fd, (struct sockaddr*)&ws->addr, &addrlen);
        if (*client_fd < 0) {
            free(client_fd);
            continue;
        }

        client_args_t *args = malloc(sizeof(client_args_t));
        args->fd = *client_fd;
        args->cb = event_callback;

        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, args);
        pthread_detach(tid);
        free(client_fd);
    }
    return true;
}



void ws_send_binary(int fd, const uint8_t *data, size_t len) {
    uint8_t hdr[10];
    int hlen = 0;
    hdr[0] = 0x82; // FIN + binary

    if (len < 126) {
        hdr[1] = len;
        hlen = 2;
    } else if (len <= 0xFFFF) {
        hdr[1] = 126;
        hdr[2] = (len >> 8) & 0xFF;
        hdr[3] = len & 0xFF;
        hlen = 4;
    } else {
        hdr[1] = 127;
        for (int i = 0; i < 8; i++)
            hdr[9 - i] = (len >> (i * 8)) & 0xFF;
        hlen = 10;
    }

    write(fd, hdr, hlen);
    write(fd, data, len);
}

void ws_close(WsState *ws) {
    close(ws->fd);
    free(ws);
}
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct {
    int fd;
    struct sockaddr_in addr;
} WsState;

typedef struct {
    int type;
    int user_id;
    uint8_t *bytes;
    uint64_t len;
} WsBinaryMessageEvent;

typedef struct {
    int type;
    int user_id;
} WsConnectionEvent;

typedef union {
    int type;
    WsConnectionEvent conn;
    WsBinaryMessageEvent msg;
} WsEvent;

typedef enum {
    WS_EVENT_CONNECT,
    WS_EVENT_DISCONNECT,
    WS_EVENT_BINARY_MESSAGE,
} WsEventType;

typedef struct {
    uint8_t fin;
    uint8_t opcode;
    uint64_t payload_len;
    uint8_t *payload;
} WsFrame;

typedef void (*WsCallback)(WsEvent *e);

WsState *ws_listen(uint16_t port);
void ws_close(WsState *ws);
bool ws_loop(WsState *ws, WsCallback event_callback);
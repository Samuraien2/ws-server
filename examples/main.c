#include <stdio.h>
#include "../ws/ws.h"

void on_event(WsEvent *event) {
    WsEvent e = *event;
    if (e.type == WS_EVENT_BINARY_MESSAGE) {
        printf("MSG Received: %lu\n[", e.msg.len);
        for (int i = 0; i < e.msg.len; i++) {
            printf("%d,", e.msg.bytes[i]);
        }
        printf("]\n");
    }
    if (e.type == WS_EVENT_CONNECT) {
        printf("%d connected\n", e.conn.user_id);
    }
    if (e.type == WS_EVENT_DISCONNECT) {
        printf("%d disconnected\n", e.conn.user_id);
    }
}

int main() {
    WsState *ws = ws_listen(9001);
    if (!ws) {
        printf("Failed lol\n");
        return 1;
    }
    printf("Server listening on port 9001...\n");

    ws_loop(ws, on_event);

    ws_close(ws);
    return 0;
}
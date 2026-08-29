/*
 * network_parser_v2 — new component arriving after secure_packet_parser was
 * patched. Demonstrates SENTINEL-X's Immune Memory pattern-matching against
 * a previously verified vulnerability class (untrusted length -> fixed buffer copy).
 */
#include <string.h>

#define MAX_FRAME 512

typedef struct {
    char data[MAX_FRAME];
} Frame;

void ingest_frame(Frame *f, const char *raw, int raw_len) {
    memcpy(f->data, raw, raw_len);
}

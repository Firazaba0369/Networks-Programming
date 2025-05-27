#ifndef WINBUF_H
#define WINBUF_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_DATA_SIZE 1400 // maximum data size for a single packet

typedef struct {
    uint32_t seq_num;
    uint8_t data[MAX_DATA_SIZE]; // data to be sent
    size_t len;
    bool is_last_data; // checks if this is the last data packet
    bool valid;        // whether slot is currenly in use
    bool acked;        // checks if acked with an RR (SERVER ONLY)
    bool sent;         // checks if this was sent already (SERVER ONLY)
    int resend_count;  // number of resend attempts (SERVER ONLY)
} buffer_entry_t;

typedef struct {
    buffer_entry_t *entries;
    size_t size;
} buffer_t;

typedef struct {
    buffer_t circ_buf; // malloc'd array of size window_size
    int size;          // window size
    int lower;         // lowest unacked seq num
    int current;       // next seq num to send
    int upper;         // lower + size
} window_t;

void window_init(window_t *win, int win_size);
int window_add(window_t *win, uint32_t seq_num, uint8_t *data, size_t len,
               bool is_last_data);
int window_ack(window_t *win, uint32_t ack_num);
buffer_entry_t *window_get_entry(window_t *win, uint32_t seq_num);
buffer_entry_t *window_resend(window_t *win, uint32_t seq_num);
bool window_is_open(window_t *win);
bool window_is_empty(window_t *win);
void buf_init(buffer_t *buf, size_t size);
void buf_free(buffer_t *buf);
void buffer_store(buffer_t *buf, uint32_t seq_num, uint8_t *data, size_t len,
                  bool is_last_data);
int buffer_get(buffer_t *buf, uint32_t seq_num, uint8_t *data);
int buffer_consume(
    buffer_t *buf,
    uint32_t seq_num); // mark entry as consumed (AKA data recved from server)
bool buffer_peek(buffer_t *buf, uint32_t seq_num);
bool bufferEntryIsLastPacket(buffer_t *buf, uint32_t seq_num);

#endif // WINBUF_H

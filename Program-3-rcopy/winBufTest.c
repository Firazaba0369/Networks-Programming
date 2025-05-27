#include "winbuf.h"
#include <stdio.h>
#include <string.h>

#define TEST_WINDOW_SIZE 4

int main() {
    window_t win;
    buffer_t buf;

    uint8_t sample_data[MAX_DATA_SIZE] = "Hello, World!";

    //---- Window Test ----
    printf("Initializing window...\n");
    window_init(&win, TEST_WINDOW_SIZE);

    // add some packets
    for (int i = 0; i < TEST_WINDOW_SIZE; i++) {
        int result = window_add(&win, win.current, sample_data,
                                strlen((char *)sample_data));
        printf("Added packet %d: %s\n", win.current - 1,
               result == 0 ? "OK" : "FAIL");
    }

    // try to add one more (should fail)
    int result =
        window_add(&win, win.current, sample_data, strlen((char *)sample_data));
    printf("Add when full: %s\n",
           result == 0 ? "OK (unexpected)" : "FAIL (expected)");

    // ack a packet
    window_ack(&win, 0);
    printf("Acked packet 0\n");

    // resend a packet
    buffer_entry_t *entry = window_resend(&win, 1);
    if (entry) {
        printf("Resending packet 1: %.*s\n", (int)entry->len, entry->data);
    }

    //---- Buffer Test ----
    printf("\nInitializing receiver buffer...\n");
    buf_init(&buf, TEST_WINDOW_SIZE);

    // store packet 3
    buffer_store(&buf, 3, sample_data, strlen((char *)sample_data));
    printf("Stored packet 3\n");

    // peek packet 3
    if (buffer_peek(&buf, 3)) {
        printf("Peeked packet 3: valid\n");
    } else {
        printf("Peeked packet 3: not valid\n");
    }

    // consume packet 3
    if (buffer_consume(&buf, 3) == 0) {
        printf("Consumed packet 3\n");
    }

    // try to peek it again
    if (buffer_peek(&buf, 3)) {
        printf("Peeked packet 3 after consume: still valid (error)\n");
    } else {
        printf("Peeked packet 3 after consume: cleared\n");
    }

    buf_free(&buf);
    return 0;
}

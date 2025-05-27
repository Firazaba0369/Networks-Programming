#include "winbuf.h"

void buf_init(buffer_t *buf, size_t size) {
    buf->entries = malloc(size * sizeof(buffer_entry_t));
    if (buf->entries == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    for (size_t i = 0; i < size; i++) {
        buf->entries[i].valid = false;
        buf->entries[i].acked = false;
        buf->entries[i].sent = false;
        buf->entries[i].resend_count = 0;
    }
    buf->size = size;
}

void buf_free(buffer_t *buf) {
    free(buf->entries);
    buf->entries = NULL;
    buf->size = 0;
}

void window_init(window_t *win, int win_size) {
    buf_init(&win->circ_buf, win_size);
    win->size = win_size;
    win->lower = 0;
    win->current = 0;
    win->upper = win_size;
}

int window_add(window_t *win, uint32_t seq_num, uint8_t *data, size_t len,
               bool is_last_data) {
    // create buffer entry
    int index = seq_num % win->size;
    buffer_entry_t *entry = &win->circ_buf.entries[index];
    if (entry->valid && entry->seq_num != seq_num) {
        printf("Window slot in use for different seq_num (possible unacked "
               "packet)\n");
        return -1;
    }
    entry->seq_num = seq_num;
    memcpy(entry->data, data, len);
    entry->len = len;
    entry->valid = true;
    entry->acked = false;
    entry->sent = false;
    entry->is_last_data = is_last_data;
    entry->resend_count = 0;

    // update window current frame
    win->current++;

    return 0;
}

int window_ack(window_t *win, uint32_t ack_num) {
    int ret = -1;

    // acknowledge all packets from lower up to (but not including) ack_num
    for (uint32_t i = win->lower; i < ack_num; i++) {
        int index = i % win->size;
        buffer_entry_t *entry = &win->circ_buf.entries[index];

        if (entry->valid && entry->seq_num == i) {
            entry->acked = true;
            ret = 0;
        }
    }

    // slide window forward as far as possible from win->lower
    while (win->lower < ack_num) {
        int low_index = win->lower % win->size;
        buffer_entry_t *low_entry = &win->circ_buf.entries[low_index];

        if (low_entry->valid && low_entry->acked &&
            low_entry->seq_num == win->lower) {
            low_entry->valid = false;
            win->lower++;
            win->upper = win->lower + win->size;
        } else {
            break; // stop sliding if we hit unacked or invalid entry
        }
    }

    return ret;
}

buffer_entry_t *window_get_entry(window_t *win, uint32_t seq_num) {
    int index = seq_num % win->size;
    buffer_entry_t *entry = &win->circ_buf.entries[index];
    if (entry->valid && entry->seq_num == seq_num) {
        return entry;
    }
    return NULL; // not found
}

buffer_entry_t *window_resend(window_t *win, uint32_t seq_num) {
    int index = seq_num % win->size;
    buffer_entry_t *entry = &win->circ_buf.entries[index];
    if (entry->resend_count >= 10) {
        return NULL; // don't resend if max attempts reached
    }

    if (entry->valid && entry->seq_num == seq_num) {
        entry->resend_count++;
        entry->sent = true;
        return entry; // caller handles sending
    }
    return NULL;
}

bool window_is_open(window_t *win) {
    // check if the current sequence number is less than the upper limit
    return (win->current < win->upper);
}

bool window_is_empty(window_t *win) {
    // check if the current sequence number is equal to the lower limit
    return (win->current == win->lower);
}

void buffer_store(buffer_t *buf, uint32_t seq_num, uint8_t *data, size_t len,
                  bool is_last_data) {
    int index = seq_num % buf->size;
    buffer_entry_t *entry = &buf->entries[index];

    // collision check
    if (entry->valid && entry->seq_num != seq_num) {
        printf(
            "Collision detected: slot for seq %u is already holding seq %u\n",
            seq_num, entry->seq_num);
        return;
    }

    // write to buffer
    entry->seq_num = seq_num;
    memcpy(entry->data, data, len);
    entry->len = len;
    entry->is_last_data = is_last_data;
    entry->valid = true;
    entry->acked = false;
    entry->sent = false;
    entry->resend_count = 0;
}

int buffer_get(buffer_t *buf, uint32_t seq_num, uint8_t *data) {
    int index = seq_num % buf->size;
    buffer_entry_t *entry = &buf->entries[index];

    if (entry->valid && entry->seq_num == seq_num) {
        memcpy(data, entry->data, entry->len);
        return entry->len;
    }

    return -1; // not found
}

bool bufferEntryIsLastPacket(buffer_t *buf, uint32_t seq_num) {
    int index = seq_num % buf->size;
    buffer_entry_t *entry = &buf->entries[index];

    if (entry->valid && entry->seq_num == seq_num) {
        return entry->is_last_data;
    }

    return false; // not found or not last data
}

bool buffer_peek(buffer_t *buf, uint32_t seq_num) {
    int index = seq_num % buf->size;
    buffer_entry_t *entry = &buf->entries[index];

    return entry->valid && entry->seq_num == seq_num;
}

int buffer_consume(buffer_t *buf, uint32_t seq_num) {
    int index = seq_num % buf->size;
    buffer_entry_t *entry = &buf->entries[index];
    if (entry->valid && entry->seq_num == seq_num) {
        entry->valid = false;
        entry->acked = false;
        entry->sent = false;
        entry->is_last_data = false;
        entry->resend_count = 0;
        return 0;
    }

    return -1;
}

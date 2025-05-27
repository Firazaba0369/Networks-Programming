#include "handle.h"

void setupHandleTable(table_t *handle_table) {
    // allocate memory for the handle table
    handle_table->handles = malloc(DEFAULT_CAP * sizeof(handle_t));
    if (handle_table->handles == NULL) {
        perror("Failed to allocate memory for handle table");
        return;
    }

    // initialize the handle table
    handle_table->num_handles = 0;
    handle_table->capacity = DEFAULT_CAP;

    // initialize the handles to 0
    for (int i = 0; i < handle_table->capacity; i++) {
        handle_table->handles[i] = (handle_t){0};
    }

    return;
}

void addHandle(table_t *handle_table, handle_t handle) {
    if (handle_table->num_handles >= handle_table->capacity) {
        // grow the table if needed
        growTable(handle_table);
    }

    // add the handle to the table
    for (int i = 0; i < handle_table->capacity; i++) {
        if (handle_table->handles[i].handle_name[0] == '\0' &&
            handle_table->handles[i].socket_num == 0) {
            handle_table->handles[i] = handle;
            handle_table->handles[i].socket_num = handle.socket_num;
            handle_table->num_handles++;
            break;
        }
    }
}

void growTable(table_t *handle_table) {
    // store old capacity
    int old_capacity = handle_table->capacity;

    // double the capacity of the table
    handle_table->capacity *= 2;

    // allocate new memory for the handles
    handle_t *new_handles = realloc(handle_table->handles,
                                    handle_table->capacity * sizeof(handle_t));
    if (new_handles == NULL) {
        perror("Failed to grow handle table");
        exit(EXIT_FAILURE);
    }

    handle_table->handles = new_handles;

    // initialize the new handles to 0
    for (int i = old_capacity; i < handle_table->capacity; i++) {
        handle_table->handles[i] = (handle_t){0};
    }
}

int lookupHandle(table_t *handle_table, const char *handle_name) {
    for (int i = 0; i < handle_table->capacity; i++) {
        if (handle_table->handles[i].handle_name[0] != '\0' &&
            strcmp(handle_table->handles[i].handle_name, handle_name) == 0) {
            return i;
        }
    }

    // handle not found
    return -1;
}

int lookupSocket(table_t *handle_table, int socket_num) {
    for (int i = 0; i < handle_table->capacity; i++) {
        if (handle_table->handles[i].handle_name[0] != '\0' &&
            handle_table->handles[i].socket_num == socket_num) {
            return i;
        }
    }

    // handle not found
    return -1;
}

void removeHandle(table_t *handle_table, handle_t handle) {
    for (int i = 0; i < handle_table->capacity; i++) {
        if (handle_table->handles[i].handle_name[0] != '\0' &&
            strcmp(handle_table->handles[i].handle_name, handle.handle_name) ==
                0) {
            // remove the handle from the table
            handle_table->handles[i].handle_name[0] = '\0';
            handle_table->handles[i].socket_num = 0;
            handle_table->handles[i] = (handle_t){0};
            handle_table->num_handles--;
            return;
        }
    }
}
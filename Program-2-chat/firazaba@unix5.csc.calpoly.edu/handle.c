#include "handle.h"

void addHandle(table_t *handle_table, handle_t handle){
    if (handle_table->num_handles >= handle_table->capacity) {
        // grow the table if needed
        growTable(handle_table);
    }

    // add the handle to the table
    for(int i = 0; i < handle_table->capacity; i++){
        if (handle_table->handles[i].handleName[0] == '\0'){
            handle_table->handles[i] = handle;
            handle_table->num_handles++;
            break;
        }
    }
}

void growTable(table_t *handle_table){
    //store old capacity
    int old_capacity = handle_table->capacity;

    // double the capacity of the table
    handle_table->capacity *= 2;
    
    // allocate new memory for the handles
    handle_t *new_handles = realloc(handle_table->handles, handle_table->capacity * sizeof(handle_t));
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

int lookupHandle(table_t *handle_table, handle_t handle){
    for(int i = 0; i < handle_table->capacity; i++){
        if (handle_table->handles[i].handleName[0] != '\0' &&
            strcmp(handle_table->handles[i].handleName, handle.handleName) == 0) {
            return i;
        }
    }

    // handle not found
    return -1;
}

void removeHandle(table_t *handle_table, handle_t handle){
    for(int i = 0; i < handle_table->capacity; i++){
        if (handle_table->handles[i].handleName[0] != '\0' &&
            strcmp(handle_table->handles[i].handleName, handle.handleName) == 0) {
            // remove the handle from the table
            handle_table->handles[i] = (handle_t){0};
            handle_table->num_handles--;
            return;
        }
    }
}
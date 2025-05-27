#include "handle.h"

int main(){
    table_t handle_table;
    handle_table.num_handles = 0;
    handle_table.capacity = 2;
    handle_table.handles = malloc(handle_table.capacity * sizeof(handle_t));
    
    if (handle_table.handles == NULL) {
        perror("Failed to allocate memory for handle table");
        exit(EXIT_FAILURE);
    }
    
    // Initialize the handles to 0
    for (int i = 0; i < handle_table.capacity; i++) {
        handle_table.handles[i] = (handle_t){0};
    }

    handle_t new_handle;
    for(int i = 1; i < 12; i++){
        // Add a new handle
        sprintf(new_handle.handle_name, "test_handle%d", i);
        new_handle.socket_num = i;

        addHandle(&handle_table, new_handle);
    }

    printf("Table Capacity: %d\n", handle_table.capacity);

    handle_t fake_handle;
    sprintf(fake_handle.handle_name, "fake_handle");
    fake_handle.socket_num = 14;

    // Lookup the handle
    int index = lookupHandle(&handle_table, new_handle.handle_name);
    if (index != -1) {
        printf("Handle found at index: %d\n", index);
        printf("Handle Name: %s, Socket Number: %d\n",
               handle_table.handles[index].handle_name,
               handle_table.handles[index].socket_num);
    } else {
        printf("Handle not found\n");
    }
    
    // Remove the handle
    removeHandle(&handle_table, fake_handle);
    
    // Free the allocated memory
    free(handle_table.handles);
    
    return 0;
}
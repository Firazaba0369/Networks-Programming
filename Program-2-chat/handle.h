#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_HANDLE 100
#define DEFAULT_CAP 2

typedef struct handle_t {
    char handle_name[MAX_HANDLE];
    int socket_num;
} handle_t;

typedef struct table_t {
    handle_t *handles;
    int num_handles;
    int capacity;
} table_t;

void setupHandleTable(table_t *handle_table);
void addHandle(table_t *handle_table, handle_t handle);
void growTable(table_t *handle_table);
int lookupHandle(table_t *handle_table, const char *handle_name);
int lookupSocket(table_t *handle_table, int socket_num);
void removeHandle(table_t *handle_table, handle_t handle);
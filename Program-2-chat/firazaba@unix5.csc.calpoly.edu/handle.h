#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define MAX_HANDLE 100
#define MAXBUF 1024
#define MAX_MULTICAST 7
#define MAX_MESSAGE 200
#define DEFAULT_CAP 10


typedef struct handle_t{
    char handleName[MAX_HANDLE];
    int socket_num;
} handle_t;

typedef struct table_t{
    handle_t *handles;
    int num_handles;
    int capacity;
} table_t;

void addHandle(table_t *handle_table, handle_t handle);
void growTable(table_t *handle_table);
int lookupHandle(table_t *handle_table, handle_t handle);
void removeHandle(table_t *handle_table, handle_t handle);
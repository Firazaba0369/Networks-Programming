/******************************************************************************
 * myServer.c
 *
 * Writen by Prof. Smith, updated Jan 2023
 * Use at your own risk.
 *
 *****************************************************************************/
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "handle.h"
#include "networks.h"
#include "pdu.h"
#include "pollLib.h"
#include "safeUtil.h"
#include <stdint.h>

// max values
#define MAXBUF 1024
#define MAX_PACKET 1400
#define MAX_MULTICAST 7
#define MAX_MESSAGE 200

// debug flag
#define DEBUG_FLAG 1

// initial packet flags
#define INITIAL_PACKET_FLAG 1
#define INITIAL_PACKET_CONFIRM 2
#define INITIAL_PACKET_ERROR 3

// command flags
#define MESSAGE_FLAG 5
#define BROADCAST_FLAG 4
#define MULTICAST_FLAG 6
#define LIST_REQUEST_FLAG 10

// destination handle error
#define DEST_HANDLE_ERROR 7

// list handles flags
#define NUM_HANDLES_FLAG 11
#define LIST_HANDLES_FLAG 12
#define LIST_COMPLETE_FLAG 13

// server control functions
int checkArgs(int argc, char *argv[]);
void serverControl(int mainServerSocket, table_t *handle_table);
void addNewSocket(int mainServerSocket);
void processClient(int clientSocket, table_t *handle_table);
void recvFromClient(int clientSocket, table_t *handle_table);

// process packet functions (server side)
int processPacket(int clientSocket, table_t *handle_table, uint8_t *packet,
                  int packet_len);
int processInitialPacket(int clientSocket, table_t *handle_table,
                         uint8_t *packet);
int processMessagePacket(int clientSocket, table_t *handle_table,
                         uint8_t *packet, int packet_len);
int processBroadcastPacket(int clientSocket, table_t *handle_table,
                           uint8_t *packet, int packet_len);
int processMulticastPacket(int clientSocket, table_t *handle_table,
                           uint8_t *packet, int packet_len);
int processListRequestPacket(int clientSocket, table_t *handle_table);

int main(int argc, char *argv[]) {
    int mainServerSocket = 0; // socket descriptor for the server socket
    int portNumber = 0;
    table_t handle_table = {0};
    setupHandleTable(&handle_table);

    // get port information
    portNumber = checkArgs(argc, argv);

    // create the server socket
    mainServerSocket = tcpServerSetup(portNumber);

    // handle the server
    serverControl(mainServerSocket, &handle_table);

    free(handle_table.handles);
    return 0;
}

void serverControl(int mainServerSocket, table_t *handle_table) {
    setupPollSet();
    addToPollSet(mainServerSocket);

    while (1) {
        int socket_num = pollCall(POLL_WAIT_FOREVER);
        if (socket_num == mainServerSocket) {
            addNewSocket(socket_num);
        } else {
            processClient(socket_num, handle_table);
        }
    }
}

void addNewSocket(int mainServerSocket) {
    // process new connection
    int clientSocket = tcpAccept(mainServerSocket, DEBUG_FLAG);
    addToPollSet(clientSocket);
}

void processClient(int clientSocket, table_t *handle_table) {
    uint8_t packet[MAX_PACKET] = {0};
    int messageLen = 0;

    // get the data from the client_socket
    if ((messageLen = recvPDU(clientSocket, packet, MAXBUF)) < 0) {
        perror("recv call");
        exit(-1);
    }

    if (messageLen > 0) {
        int bytes_sent =
            processPacket(clientSocket, handle_table, packet, messageLen);
        if (bytes_sent < 0) {
            fprintf(stderr, "processPacket call error\n");
            return;
        }
    } else if (messageLen == 0) {
        // connection closed by other side
        printf("Socket %d: Connection closed by other side\n", clientSocket);

        // close the sockets
        close(clientSocket);
        removeFromPollSet(clientSocket);
        int handle_index = lookupSocket(handle_table, clientSocket);
        removeHandle(handle_table, handle_table->handles[handle_index]);
    }
}

int processPacket(int clientSocket, table_t *handle_table, uint8_t *packet,
                  int packet_len) {
    switch ((int)(packet[0])) {
    case INITIAL_PACKET_FLAG:
        return processInitialPacket(clientSocket, handle_table, packet);
    case MESSAGE_FLAG:
        return processMessagePacket(clientSocket, handle_table, packet,
                                    packet_len);
    case BROADCAST_FLAG:
        return processBroadcastPacket(clientSocket, handle_table, packet,
                                      packet_len);
    case MULTICAST_FLAG:
        return processMulticastPacket(clientSocket, handle_table, packet,
                                      packet_len);
    case LIST_REQUEST_FLAG:
        return processListRequestPacket(clientSocket, handle_table);
    default:
        fprintf(stderr, "Invalid Flag: %d\n", packet[0]);
        return -1;
    }
}

int processInitialPacket(int clientSocket, table_t *handle_table,
                         uint8_t *packet) {
    handle_t new_handle = (handle_t){0};
    int packet_idx = 1; // skip the flag
    int sent = 0;

    // fill the handle name into the packet
    int handle_len = packet[packet_idx++];
    memcpy(new_handle.handle_name, packet + packet_idx, handle_len);
    new_handle.handle_name[handle_len] = '\0'; // Null-terminate
    packet_idx += handle_len;
    int res = lookupHandle(handle_table, new_handle.handle_name);
    if (res >= 0) {
        // handle already exists
        fprintf(stderr, "Handle '%s' already exists\n", new_handle.handle_name);
        uint8_t error_packet[1];
        error_packet[0] = INITIAL_PACKET_ERROR;
        sendPDU(clientSocket, error_packet, 1);
        return -1;
    } else {
        // add new handle to the table
        new_handle.socket_num = clientSocket;
        addHandle(handle_table, new_handle);

        // send confirmation packet
        uint8_t confirm_packet[1];
        confirm_packet[0] = INITIAL_PACKET_CONFIRM;
        sent = sendPDU(clientSocket, confirm_packet, 1);
        if (sent < 0) {
            fprintf(stderr, "sendPDU call error\n");
            return -1;
        }
    }

    return sent;
}

int processMessagePacket(int clientSocket, table_t *handle_table,
                         uint8_t *packet, int packet_len) {
    int sending_handle_len = 0;
    int dest_handle_len = 0;
    char dest_handle_name[MAX_HANDLE];
    int packet_idx = 1; // skip the flag

    sending_handle_len = packet[packet_idx++];
    packet_idx += sending_handle_len; // skip the sending handle
    packet_idx++;                     // skip the number of destination handles

    // get the destination handle
    dest_handle_len = packet[packet_idx++];
    memcpy(dest_handle_name, packet + packet_idx, dest_handle_len);
    dest_handle_name[dest_handle_len] = '\0'; // Null-terminate
    packet_idx += dest_handle_len;            // skip the destination handle

    // lookup the destination handle
    int dest_handle_index = lookupHandle(handle_table, dest_handle_name);
    if (dest_handle_index < 0) {
        fprintf(stderr, "Client with handle '%s' does not exist\n",
                dest_handle_name);
        uint8_t error_packet[MAX_HANDLE + 2];
        error_packet[0] = DEST_HANDLE_ERROR;
        error_packet[1] = dest_handle_len;
        memcpy(error_packet + 2, dest_handle_name, dest_handle_len);
        sendPDU(clientSocket, error_packet, dest_handle_len + 2);
        return -1;
    }

    // send the message to the destination handle
    int sent = sendPDU(handle_table->handles[dest_handle_index].socket_num,
                       packet, packet_len);
    if (sent < 0) {
        fprintf(stderr, "sendPDU call error\n");
        return -1;
    }
    return sent;
}

int processBroadcastPacket(int clientSocket, table_t *handle_table,
                           uint8_t *packet, int packet_len) {
    int sent = 0;
    for (int i = 0; i < handle_table->num_handles; i++) {
        if (handle_table->handles[i].socket_num != clientSocket) {
            // send the message to the destination handle
            sent = sendPDU(handle_table->handles[i].socket_num, packet,
                           packet_len);
            if (sent < 0) {
                fprintf(stderr, "sendPDU call error\n");
                return -1;
            }
        }
    }
    return sent;
}

int processMulticastPacket(int clientSocket, table_t *handle_table,
                           uint8_t *packet, int packet_len) {
    int sending_handle_len = 0;
    int num_dest_handles = 0;
    int dest_handle_len = 0;
    char dest_handle_name[MAX_HANDLE];
    int packet_idx = 1; // skip the flag
    int total_sent = 0; // total bytes sent

    sending_handle_len = packet[packet_idx++];
    packet_idx += sending_handle_len; // skip the sending handle
    num_dest_handles =
        (int)(packet[packet_idx++]); // get the number of destination handles
    for (int i = 0; i < num_dest_handles; i++) {
        // get the destination handle
        dest_handle_len = packet[packet_idx++];
        memcpy(dest_handle_name, packet + packet_idx, dest_handle_len);
        dest_handle_name[dest_handle_len] = '\0'; // Null-terminate
        packet_idx += dest_handle_len; // increment by the destination handle

        // lookup the destination handle
        int dest_handle_index = lookupHandle(handle_table, dest_handle_name);
        if (dest_handle_index < 0) {
            fprintf(stderr, "Client with handle '%s' does not exist\n",
                    dest_handle_name);
            uint8_t error_packet[MAX_HANDLE + 2];
            error_packet[0] = DEST_HANDLE_ERROR;
            error_packet[1] = dest_handle_len;
            memcpy(error_packet + 2, dest_handle_name, dest_handle_len);
            sendPDU(clientSocket, error_packet, dest_handle_len + 2);
            continue;
        }

        // send the message to the destination handle
        int sent = sendPDU(handle_table->handles[dest_handle_index].socket_num,
                           packet, packet_len);
        if (sent < 0) {
            fprintf(stderr, "sendPDU call error\n");
            return -1;
        }

        total_sent += sent;
    }

    return total_sent;
}

int processListRequestPacket(int clientSocket, table_t *handle_table) {
    // send confirmation packet
    int total_sent = 0;
    uint8_t num_handles_packet[5];
    num_handles_packet[0] = NUM_HANDLES_FLAG; // header flag

    // send number of handles
    uint32_t handle_count = htonl(handle_table->num_handles);
    memcpy(num_handles_packet + 1, &handle_count, sizeof(uint32_t)); // 4 bytes
    int sent = sendPDU(clientSocket, num_handles_packet, 5);
    if (sent < 0) {
        fprintf(stderr, "sendPDU call error\n");
        return -1;
    }
    total_sent += sent;

    // send handles one by one
    for (int i = 0; i < handle_table->num_handles; i++) {
        uint8_t list_packet[MAX_HANDLE + 2];
        int handle_len = strlen(handle_table->handles[i].handle_name);
        list_packet[0] = LIST_HANDLES_FLAG; // list handles flag
        list_packet[1] = handle_len;        // length of handle
        memcpy(list_packet + 2, handle_table->handles[i].handle_name,
               handle_len);
        list_packet[handle_len + 2] = '\0'; // Null-terminate

        sent = sendPDU(clientSocket, list_packet, handle_len + 3);
        if (sent < 0) {
            fprintf(stderr, "sendPDU call error\n");
            return -1;
        }

        total_sent += sent;
    }

    // send completion flag
    uint8_t list_complete_packet[1];
    list_complete_packet[0] = LIST_COMPLETE_FLAG; // list complete flag
    sent = sendPDU(clientSocket, list_complete_packet, 1);
    if (sent < 0) {
        fprintf(stderr, "sendPDU call error\n");
        return -1;
    }
    total_sent += sent;

    return total_sent;
}

void recvFromClient(int clientSocket, table_t *handle_table) {
    uint8_t packet[MAX_PACKET] = {0};
    int messageLen = 0;

    // get the data from the client_socket
    if ((messageLen = recvPDU(clientSocket, packet, MAXBUF)) < 0) {
        perror("recv call");
        exit(-1);
    }

    if (messageLen > 0) {
        int bytes_sent =
            processPacket(clientSocket, handle_table, packet, messageLen);
        if (bytes_sent < 0) {
            fprintf(stderr, "processPacket call error\n");
            return;
        }
    } else if (messageLen == 0) {
        /* connection closed by other side */
        printf("Socket %d: Connection closed by other side\n", clientSocket);

        /* close the sockets */
        close(clientSocket);
        removeFromPollSet(clientSocket);
        int handle_index = lookupSocket(handle_table, clientSocket);
        removeHandle(handle_table, handle_table->handles[handle_index]);
    }
}

int checkArgs(int argc, char *argv[]) {
    // Checks args and returns port number
    int portNumber = 0;

    if (argc > 2) {
        fprintf(stderr, "Usage %s [optional port number]\n", argv[0]);
        exit(-1);
    }

    if (argc == 2) {
        portNumber = atoi(argv[1]);
    }

    return portNumber;
}
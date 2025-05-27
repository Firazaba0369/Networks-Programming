#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
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
#define INTIAL_PACKET_ERROR 3

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

// client control functions
void sendToServer(int socketNum);
int readFromStdin(uint8_t *buffer);
void checkArgs(int argc, char *argv[]);
void clientControl(handle_t *handle);
void processStdin(handle_t *handle);
void processMsgFromServer(int socketNum);
int sendInitialPacket(handle_t *handle);
int intialPacketStatus(handle_t *handle);

// process command functions + helper functions
int processCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet);
int processMessageCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet);
int processBroadcastCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet);
int processMulticastCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet);
int processListRequestCommand(handle_t *handle);
int sendPacket(handle_t *handle, uint8_t *packet, int packet_idx,
               char *message);

// process packet functions (client side)
int processPacket(int socketNum, uint8_t *packet);
int processMessagePacket(uint8_t *packet);
int processBroadcastPacket(uint8_t *packet);
int processMulticastPacket(uint8_t *packet);
void processNumHandles(int socketNum, uint8_t *packet);
void processHandles(int socketNum, uint8_t *packet);

int main(int argc, char *argv[]) {
    handle_t handle = {0};
    int sent = 0;

    // parse command line arguments for client info
    checkArgs(argc, argv);

    for(int i = 0; i < 300; i++){
        sprintf(handle.handle_name, "test%d", i); // creates a new handle name 
        handle.socket_num = tcpClientSetup(argv[2], argv[3], DEBUG_FLAG);
        sent = sendInitialPacket(&handle);
        if (sent < 0) {
            fprintf(stderr, "sendInitialPacket call error\n");
            exit(-1);
        }
    }

    clientControl(&handle);

    return 0;
}

int sendInitialPacket(handle_t *handle) {
    uint8_t packet[MAX_PACKET] = {0};
    int packet_idx = 0;
    int bytes_sent = 0;

    // fill the initial packet flag into the packet
    packet[packet_idx++] = INITIAL_PACKET_FLAG;

    // fill the handle name into the packet
    packet[packet_idx++] = strlen(handle->handle_name); // length of handle
    memcpy(packet + packet_idx, handle->handle_name,
           strlen(handle->handle_name));
    packet_idx += strlen(handle->handle_name);

    // send the initial packet to the server
    bytes_sent = sendPDU(handle->socket_num, packet, packet_idx);
    if (bytes_sent < 0) {
        fprintf(stderr, "sendPDU call error\n");
        return -1;
    }

    // check initial packet status
    int status = intialPacketStatus(handle);
    if (status < 0) {
        fprintf(stderr, "intialPacketStatus call error\n");
        return -1;
    }

    return bytes_sent;
}

int intialPacketStatus(handle_t *handle) {
    // Buffer to receive the response
    uint8_t initial_packet_flag[1];
    int bytes_received = recvPDU(handle->socket_num, initial_packet_flag,
                                 sizeof(initial_packet_flag));
    if (bytes_received < 0) {
        perror("recvPDU call error");
        return -1;
    }

    // check the response
    if (initial_packet_flag[0] == INITIAL_PACKET_CONFIRM) {
        // Handle confirmed
        return 0;
    } else if (initial_packet_flag[0] == INTIAL_PACKET_ERROR) {
        // Handle already exists
        fprintf(stderr, "Handle '%s' already exists\n", handle->handle_name);
        return -1;
    } else {
        // Unexpected flag
        fprintf(stderr, "Invalid flag received: %d\n", initial_packet_flag[0]);
        return -1;
    }
}

void clientControl(handle_t *handle) {
    // configure the poll set
    setupPollSet();
    addToPollSet(handle->socket_num);
    addToPollSet(STDIN_FILENO);

    while (1) {
        printf("\r$: ");
        fflush(stdout);
        int socket_num = pollCall(POLL_WAIT_FOREVER);
        if (socket_num == STDIN_FILENO) {
            processStdin(handle);
        } else {
            printf("\r");
            fflush(stdout);
            processMsgFromServer(socket_num);
        }
    }
}

void processStdin(handle_t *handle) {
    uint8_t buffer[MAX_PACKET] = {0};
    uint8_t packet[MAX_PACKET] = {0};
    int sendLen = 0;
    int sent = 0; // actual amount of data sent

    // get the data from stdin
    sendLen = readFromStdin(buffer);
    if (sendLen == MAX_PACKET && buffer[MAX_PACKET - 2] != '\n') {
        // the buffer filled up and we didn't see a newline
        fprintf(stderr, "Warning: Message exceeded 1400 bytes. Only the first "
                        "1400 bytes were sent.\n");

        // flush the rest of stdin so it doesn't mess up next read
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
    }

    // process the command
    sent = processCommand(handle, buffer, packet);
    if (sent < 0) {
        fprintf(stderr, "Invalid Command\n");
        return;
    }
}

void processMsgFromServer(int socketNum) {
    uint8_t packet[MAX_PACKET] = {0};

    // get the data from the sever
    int recvBytes = recvPDU(socketNum, packet, MAX_PACKET);
    if (recvBytes == 0) {
        printf("Server has terminated\n");
        removeFromPollSet(socketNum);
        close(socketNum);
        exit(0);
    }

    // process the packet
    int status = processPacket(socketNum, packet);
    if (status < 0) {
        fprintf(stderr, "processPacket call error\n");
        return;
    }
}

int processPacket(int socketNum, uint8_t *packet) {
    // check the packet flag
    switch ((int)packet[0]) {
    case MESSAGE_FLAG:
        return processMessagePacket(packet);
    case BROADCAST_FLAG:
        return processBroadcastPacket(packet);
    case MULTICAST_FLAG:
        return processMulticastPacket(packet);
    case NUM_HANDLES_FLAG:
        processNumHandles(socketNum, packet);
        return 1;
    case LIST_HANDLES_FLAG:
        processHandles(socketNum, packet);
        return 1;
    case LIST_COMPLETE_FLAG:
        return 1; // no action needed
    default:
        fprintf(stderr, "Invalid packet flag: %c\n", (char)packet[0]);
        return -1;
    }
}

int processMessagePacket(uint8_t *packet) {
    char sender_handle_name[MAX_HANDLE];      
    int packet_idx = 1;                           // start after the flag
    int sender_handle_len = packet[packet_idx++]; // length of handle
    memcpy(sender_handle_name, packet + packet_idx,
           sender_handle_len);                    // copy the handle name
    sender_handle_name[sender_handle_len] = '\0'; // null-terminate
    packet_idx += sender_handle_len;              // increment the packet index
    packet_idx++; // skip the number of destination handles
    int dest_handles_len =
        packet[packet_idx++];       // skip the destination handle length
    packet_idx += dest_handles_len; // skip the destination handle
    uint8_t *message = packet + packet_idx; // get the message

    // print the client info and message
    printf("%s: %s\n", sender_handle_name, message);
    return 0;
}

int processBroadcastPacket(uint8_t *packet) {
    char sender_handle_name[MAX_HANDLE];      
    int packet_idx = 1;                           // start after the flag
    int sender_handle_len = packet[packet_idx++]; // length of handle
    memcpy(sender_handle_name, packet + packet_idx,
           sender_handle_len);              // copy the handle name
    packet_idx += sender_handle_len;        // increment the packet index
    uint8_t *message = packet + packet_idx; // get the message

    // print the client info and message
    printf("%s: %s\n", sender_handle_name, message);
    return 0;
}

int processMulticastPacket(uint8_t *packet) {
    char sender_handle_name[MAX_HANDLE];
    int num_handles = 0;
    int packet_idx = 1;                           // start after the flag
    int sender_handle_len = packet[packet_idx++]; // length of handle
    memcpy(sender_handle_name, packet + packet_idx,
           sender_handle_len);                    // copy the handle name
    sender_handle_name[sender_handle_len] = '\0'; // null-terminate
    packet_idx += sender_handle_len;              // increment the packet index
    num_handles = packet[packet_idx++]; // get the number of destination handles
    for (int i = 0; i < num_handles; i++) {
        int dest_handle_len =
            packet[packet_idx++];      // length of destination handle
        packet_idx += dest_handle_len; // increment the packet index
    }
    uint8_t *message = packet + packet_idx; // get the message

    // print the client info and message
    printf("%s: %s\n", sender_handle_name, message);
    return 0;
}

void processNumHandles(int socketNum, uint8_t *packet) {
    uint32_t num_handles = 0;

    // extract number of handles and print it
    uint32_t num_handles_net;
    memcpy(&num_handles_net, packet + 1, sizeof(uint32_t));
    num_handles = ntohl(num_handles_net);
    printf("Number of clients: %d\n", num_handles);
    return;
}

void processHandles(int socketNum, uint8_t *packet) {
    char handle_name[MAX_HANDLE]; 
    int handle_name_len = packet[1];

    // print the handle name
    memcpy(handle_name, packet + 2, handle_name_len);
    handle_name[handle_name_len] = '\0'; // null-terminate
    printf("\r %s\n", handle_name);
}

int processCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet) {
    if (buffer[0] != '%') {
        // invalid command
        fprintf(stderr, "Invalid command format\n");
        return -1;
    }

    switch (tolower(buffer[1])) {
    case 'm':
        return processMessageCommand(handle, buffer, packet);
    case 'b':
        return processBroadcastCommand(handle, buffer, packet);
    case 'c':
        return processMulticastCommand(handle, buffer, packet);
    case 'l':
        return processListRequestCommand(handle);
    default:
        // invalid command
        fprintf(stderr, "Invalid command format\n");
        return -1;
    }
}

int processMessageCommand(handle_t *handle, uint8_t *buffer, uint8_t *packet) {
    int packet_idx = 0;
    int dest_handle_len = 0;
    char *token = strtok((char *)buffer, " "); // skip the command

    // fill the message flag into the packet
    packet[packet_idx++] = MESSAGE_FLAG; //%M flag

    // fill sending client handle info into the packet
    packet[packet_idx++] = strlen(handle->handle_name); // length of handle
    memcpy(packet + packet_idx, handle->handle_name,
           strlen(handle->handle_name));
    packet_idx += strlen(handle->handle_name);

    // fill destination handle info into the packet
    packet[packet_idx++] =
        1; // # of destination handles (always 1 for message packet)
    token = strtok(NULL, " ");
    dest_handle_len = strlen(token);
    if (dest_handle_len > MAX_HANDLE - 1) {
        fprintf(stderr,
                "Invalid handle, handle longer than 100 characters: %s\n",
                token);
        return -1;
    }
    packet[packet_idx++] = dest_handle_len; // destination handle length
    memcpy(packet + packet_idx, token,
           dest_handle_len);       // copy the destination handle
    packet_idx += dest_handle_len; // increment the packet index

    char *message = strtok(NULL, ""); // store the message
    if (message == NULL) {
        message = ""; // point to a valid empty string
    }

    // send the packet to the server
    int bytes_sent = sendPacket(handle, packet, packet_idx, message);
    if (bytes_sent < 0) {
        fprintf(stderr, "sendPacket call error\n");
        return -1;
    }

    // return the number of bytes sent
    return bytes_sent;
}

int processBroadcastCommand(handle_t *handle, uint8_t *buffer,
                            uint8_t *packet) {
    int packet_idx = 0;
    char *message = strtok((char *)buffer, " "); // skip the command

    // fill the broadcast flag into the packet
    packet[packet_idx++] = BROADCAST_FLAG; //%B flag

    // fill sending client handle infor into the packet
    packet[packet_idx++] = strlen(handle->handle_name); // length of handle
    memcpy(packet + packet_idx, handle->handle_name,
           strlen(handle->handle_name));
    packet_idx += strlen(handle->handle_name);

    message = strtok(NULL, ""); // store the message
    if (message == NULL) {
        message = ""; // point to a valid empty string
    }

    // send the packet to the server
    int bytes_sent = sendPacket(handle, packet, packet_idx, message);
    if (bytes_sent < 0) {
        fprintf(stderr, "sendPacket call error\n");
        return -1;
    }

    // return the number of bytes sent
    return bytes_sent;
}

int processMulticastCommand(handle_t *handle, uint8_t *buffer,
                            uint8_t *packet) {
    int packet_idx = 0;
    int dest_handle_len = 0;
    int num_handles = 0;
    char *token = strtok((char *)buffer, " "); // skip the command

    // fill the message flag into the packet
    packet[packet_idx++] = MULTICAST_FLAG; //%C flag

    // fill sending client handle info into the packet
    packet[packet_idx++] = strlen(handle->handle_name); // length of handle
    memcpy(packet + packet_idx, handle->handle_name,
           strlen(handle->handle_name));
    packet_idx += strlen(handle->handle_name);

    // fill destination handle info into the packet
    token = strtok(NULL, " ");
    num_handles = (int)atoi(token); // number of destination handles
    if (num_handles < 2 || num_handles > 9) {
        fprintf(stderr, "Invalid number of handles: %d\n", num_handles);
        return -1;
    }
    packet[packet_idx++] = num_handles; // # of destination handles
    for (int i = 0; i < num_handles; i++) {
        token = strtok(NULL, " ");
        dest_handle_len = strlen(token);
        if (dest_handle_len > MAX_HANDLE - 1) {
            fprintf(stderr,
                    "Invalid handle, handle longer than 100 characters: %s\n",
                    token);
            return -1;
        }
        packet[packet_idx++] = dest_handle_len; // destination handle length
        memcpy(packet + packet_idx, token, dest_handle_len);
        packet_idx += dest_handle_len;
    }

    char *message = strtok(NULL, ""); // store the message
    if (message == NULL) {
        message = ""; // point to a valid empty string
    }
    // send the packet to the server
    int bytes_sent = sendPacket(handle, packet, packet_idx, message);
    if (bytes_sent < 0) {
        fprintf(stderr, "sendPacket call error\n");
        return -1;
    }

    // return the number of bytes sent
    return bytes_sent;
}

int processListRequestCommand(handle_t *handle) {
    // fill the list flag into the packet
    uint8_t packet[1];
    packet[0] = LIST_REQUEST_FLAG; //%L flag
    int sent =
        sendPDU(handle->socket_num, packet, 1); // send the packet to the server
    if (sent < 0) {
        fprintf(stderr, "sendPDU call error\n");
        return -1;
    }
    return 1;
}

int sendPacket(handle_t *handle, uint8_t *packet, int packet_idx,
               char *message) {
    int message_len = strlen(message);
    int message_start_idx = packet_idx;
    int tot_bytes_sent = message_start_idx;
    int offset = 0;
    int sent = 0;

    if (message_len == 0) {
        // send an empty message with just a null terminator
        packet[packet_idx] = '\0';
        sent = sendPDU(handle->socket_num, packet, packet_idx + 1);
        if (sent < 0) {
            fprintf(stderr, "sendPDU call error\n");
            return -1;
        }
        return sent;
    }

    // send 200 byte message(s) to the server
    while (message_len > 0) {
        int chunk_size =
            (message_len > MAX_MESSAGE - 1) ? (MAX_MESSAGE - 1) : message_len;

        // copy the message to the packet
        memcpy(packet + packet_idx, message + offset, chunk_size);
        packet[packet_idx + chunk_size] = '\0'; // Add null terminator

        int final_packet_len = packet_idx + chunk_size + 1;

        // send the packet to the server
        sent = sendPDU(handle->socket_num, packet, final_packet_len);
        if (sent < 0) {
            fprintf(stderr, "sendPDU call error\n");
            return -1;
        }
        offset += chunk_size;
        message_len -= chunk_size;
        tot_bytes_sent += packet_idx + chunk_size + 1;

        // reset packet index to reuse header
        packet_idx = message_start_idx;
    }

    return tot_bytes_sent;
}

void sendToServer(int socketNum) {
    uint8_t buffer[MAX_PACKET] = {0};
    int sendLen = 0; // amount of data to send
    int sent = 0;    // actual amount of data sent
    int recvBytes = 0;

    sendLen = readFromStdin(buffer);

    sent = sendPDU(socketNum, buffer, sendLen);
    if (sent < 0) {
        perror("send call");
        exit(-1);
    }

    // just for debugging, recv a message from the server to prove it works.
    recvBytes = recvPDU(socketNum, buffer, MAX_PACKET);

    if (recvBytes == 0) {
        printf("Server Terminated\n");
        removeFromPollSet(socketNum);
        close(socketNum);
        exit(0);
    }
}

int readFromStdin(uint8_t *buffer) {
    char aChar = 0;
    int inputLen = 0;

    // Important you don't input more characters than you have space
    buffer[0] = '\0';
    // printf("Enter data: ");
    while (inputLen < (MAX_PACKET - 1) && aChar != '\n') {
        aChar = getchar();
        if (aChar != '\n') {
            buffer[inputLen] = aChar;
            inputLen++;
        }
    }

    // Null terminate the string
    buffer[inputLen] = '\0';
    inputLen++;

    return inputLen;
}

void checkArgs(int argc, char *argv[]) {
    /* check command line arguments  */
    if (argc != 4) {
        printf("usage: %s handle server-name server-port \n", argv[0]);
        exit(1);
    }
}
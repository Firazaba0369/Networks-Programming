/******************************************************************************
 * myClient.c
 *
 * Writen by Prof. Smith, updated Jan 2023
 * Use at your own risk.
 *
 *****************************************************************************/

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

#include "networks.h"
#include "pdu.h"
#include "pollLib.h"
#include "safeUtil.h"

#define MAXBUF 1024
#define DEBUG_FLAG 1

void processStdin(int socketNum);
void processMsgFromServer(int socketNum);
void clientControl(int socketNum);

void sendToServer(int socketNum);
int readFromStdin(uint8_t *buffer);
void checkArgs(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    int socketNum = 0; // socket descriptor

    checkArgs(argc, argv);

    /* set up the TCP Client socket  */
    socketNum = tcpClientSetup(argv[1], argv[2], DEBUG_FLAG);

    clientControl(socketNum);

    return 0;
}

void sendToServer(int socketNum) {
    uint8_t buffer[MAXBUF]; // data buffer
    int sendLen = 0;        // amount of data to send
    int sent = 0; // actual amount of data sent/* get the data and send it   */
    int recvBytes = 0;

    sendLen = readFromStdin(buffer);
    printf("read: %s string len: %d (including null)\n", buffer, sendLen);

    sent = sendPDU(socketNum, buffer, sendLen);
    if (sent < 0) {
        perror("send call");
        exit(-1);
    }

    printf("Socket:%d: Sent, Length: %d msg: %s\n", socketNum, sent, buffer);

    // just for debugging, recv a message from the server to prove it works.
    recvBytes = recvPDU(socketNum, buffer, MAXBUF);
    printf("Socket %d: Byte recv: %d message: %s\n", socketNum, recvBytes,
           buffer);
    if (recvBytes == 0) {
        printf("Server has terminated\n");
        removeFromPollSet(socketNum);
        close(socketNum);
        exit(0);
    }
}

void clientControl(int socketNum) {
    // configure the poll set
    setupPollSet();
    addToPollSet(socketNum);
    addToPollSet(STDIN_FILENO);

    while (1) {
        printf("Enter data: ");
        fflush(stdout);
        int socket_num = pollCall(POLL_WAIT_FOREVER);
        if (socket_num == STDIN_FILENO) {
            processStdin(socketNum);
        } else {
            printf("\r"); 
            fflush(stdout);
            processMsgFromServer(socketNum);
        }
    }
}

void processStdin(int socketNum) {
    uint8_t buffer[MAXBUF];
    int sendLen = 0;
    int sent = 0; // actual amount of data sent/* get the data and send it   */

    sendLen = readFromStdin(buffer);

    sent = sendPDU(socketNum, buffer, sendLen);
    if (sent < 0) {
        perror("send call");
        exit(-1);
    }

    printf("Message sent on Socket: %d, Length: %d Data: %s\n", socketNum, sent,
           buffer);
}

void processMsgFromServer(int socketNum) {
    uint8_t buffer[MAXBUF]; // data buffer
    // just for debugging, recv a message from the server to prove it works.
    int recvBytes = recvPDU(socketNum, buffer, MAXBUF);
    if (recvBytes == 0) {
        printf("Server has terminated\n");
        removeFromPollSet(socketNum);
        close(socketNum);
        exit(0);
    }

    printf("Message received on Socket %d, Length: %d Data: %s\n", socketNum,
           recvBytes, buffer);
}

int readFromStdin(uint8_t *buffer) {
    char aChar = 0;
    int inputLen = 0;

    // Important you don't input more characters than you have space
    buffer[0] = '\0';
    // printf("Enter data: ");
    while (inputLen < (MAXBUF - 1) && aChar != '\n') {
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
    if (argc != 3) {
        printf("usage: %s host-name port-number \n", argv[0]);
        exit(1);
    }
}

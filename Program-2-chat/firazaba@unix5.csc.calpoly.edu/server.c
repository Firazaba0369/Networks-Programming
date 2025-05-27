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
#include <stdint.h>

#define MAXBUF 1024
#define DEBUG_FLAG 1

void serverControl(int mainServerSocket);
void addNewSocket(int mainServerSocket);
void processClient(int clientSocket);
void recvFromClient(int clientSocket);
int checkArgs(int argc, char *argv[]);

int main(int argc, char *argv[]) {
    int mainServerSocket = 0; // socket descriptor for the server socket
    int portNumber = 0;

    portNumber = checkArgs(argc, argv);

    // create the server socket
    mainServerSocket = tcpServerSetup(portNumber);

    // handle the server
    serverControl(mainServerSocket);

    return 0;
}

void recvFromClient(int clientSocket) {
    uint8_t dataBuffer[MAXBUF];
    int messageLen = 0;

    // now get the data from the client_socket
    if ((messageLen = recvPDU(clientSocket, dataBuffer, MAXBUF)) < 0) {
        perror("recv call");
        exit(-1);
    }

    if (messageLen > 0) {
        printf("Message received on Socket: %d, Length: %d Data: %s\n",
               clientSocket, messageLen, dataBuffer);

        // send it back to client (just to test sending is working... e.g.
        // debugging)
        messageLen = sendPDU(clientSocket, dataBuffer, messageLen);
        printf("Message sent on Socket: %d, Length: %d Data: %s\n",
               clientSocket, messageLen, dataBuffer);
    } else if (messageLen == 0) {
        /* connection closed by other side */
        printf("Socket %d: Connection closed by other side\n", clientSocket);

        /* close the sockets */
        close(clientSocket);
        removeFromPollSet(clientSocket);
    }
}

void serverControl(int mainServerSocket) {
    setupPollSet();
    addToPollSet(mainServerSocket);

    while (1) {
        int socket_num = pollCall(POLL_WAIT_FOREVER);
        if (socket_num == mainServerSocket) {
            addNewSocket(socket_num);
        } else {
            processClient(socket_num);
        }
    }
}

void addNewSocket(int mainServerSocket) {
    // process new connection
    int clientSocket = tcpAccept(mainServerSocket, DEBUG_FLAG);
    addToPollSet(clientSocket);
}

void processClient(int clientSocket) {
    // process client
    recvFromClient(clientSocket);
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

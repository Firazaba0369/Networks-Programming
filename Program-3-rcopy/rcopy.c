// Client side - UDP Code
// By Hugh Smith	4/1/2017

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
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

#include "checksum.h"
#include "cpe464.h"
#include "gethostbyname.h"
#include "networks.h"
#include "pdu.h"
#include "pollLib.h"
#include "safeUtil.h"
#include "winbuf.h"

// max values
#define MAX_FILENAME 100
#define MAXBUF 80
#define MAX_RETRIES 10

// flags
#define RR_PACKET 5
#define SREJ_PACKET 6
#define SETUP_PACKET 8
#define FILE_OK_PACKET 9
#define LAST_DATA_PACKET 10
#define DATA_PACKET 16
#define SREJ_RESEND_PACKET 17
#define TIMEOUT_RESEND_PACKET 18
#define FILE_OK_ACK_PACKET 32
#define TEARDOWN_PACKET 33

// status for file open
#define FILENAME_OK 34
#define FILENAME_BAD 35
#define FILENAME_OK_ACK 36

// file permissions
#define OWNER_PERMISSION 0600

// struct to hold session info
typedef struct {
    // network info
    int socketNum;
    struct sockaddr_in6 serverAddr;
    int serverAddrLen;
    char *serverName;
    int portNumber;

    // file info
    char *fromFilename;
    char *toFilename;
    int32_t outputFile_fd;

    // protocol info
    uint32_t winSize;
    uint32_t bufSize;

    // buffer
    buffer_t buffer; // buffer for out-of-order packets

    // data tracking
    uint32_t expSeqNum;
    uint32_t topSeqNum;  // last sequence number received
    uint32_t sendSeqNum; // sequence number for sending data
} session_t;

typedef enum {
    // setup states
    SETUP_SOCKET,
    SEND_FILENAME,
    WAIT_FILE_OK,
    SEND_FILE_OK_ACK,
    WAIT_FOR_DATA,

    // data states
    IN_ORDER,
    BUFFER,
    FLUSHING,

    // teardown state
    TEARDOWN,

    // done and errorstate
    DONE,
    ERROR
} state;

// state machine functions
state setupSocket(session_t *client);
state sendFilename(session_t *client);
state waitFileOk(session_t *client);
state sendFileOkAck(session_t *client);
state waitForData(session_t *client);
state in_order(session_t *client);
state buffer(session_t *client);
state flushing(session_t *client);
state teardown(session_t *client);
state error_exit(session_t *client);

// connection processing functions
int checkArgs(int argc, char *argv[]);
void processFile(char **argv);
uint32_t extractSeqNum(uint8_t *pduBuffer);
void retryConnection(session_t *client, int *count);
int validateDataPacket(uint8_t *pduBuffer, int pduLen);
int validateSetupPacket(uint8_t *pduBuffer, int pduLen);
int recvAndVal(session_t *client, uint8_t *pduBuffer, int *pduLen,
               int (*valfunc)(uint8_t *, int));
int writeDataAndAck(session_t *client, uint8_t *data, int len);
void send_SREJ(session_t *client, uint32_t seq_num);
void send_RR(session_t *client, uint32_t seq_num);
int sendTeardownPacket(session_t *client);

/**
 * @brief Main function to for the UDP client.
 *
 * @param argc
 * @param argv
 * @return Returns 0 on success, exits with error message on failure.
 */
int main(int argc, char *argv[]) {
    checkArgs(argc, argv);

    // initialize sendErr
    float error_rate = atof(argv[5]);
    sendErr_init(error_rate, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);
    setupPollSet();

    processFile(argv);

    return 0;
}

/**
 * @brief Handles the the file transfer from setup to teardown.
 *
 * @param char **argv
 * @return void
 */
void processFile(char **argv) {
    session_t client = {.socketNum = 0,
                        .serverName = argv[6],
                        .serverAddrLen = sizeof(client.serverAddr),
                        .portNumber = atoi(argv[7]),
                        .fromFilename = argv[1],
                        .toFilename = argv[2],
                        .outputFile_fd = 0,
                        .winSize = atoi(argv[3]),
                        .bufSize = atoi(argv[4]),
                        .expSeqNum = 0,
                        .topSeqNum = 0,
                        .sendSeqNum = 0};
    buf_init(&client.buffer, client.winSize);
    state curr_state = SETUP_SOCKET;

    // enter state machine
    while (curr_state != DONE) {
        switch (curr_state) {
        // setup the socket
        case SETUP_SOCKET:
            curr_state = setupSocket(&client);
            break;
        // send filename
        case SEND_FILENAME:
            curr_state = sendFilename(&client);
            break;
        // wait for file ok
        case WAIT_FILE_OK:
            curr_state = waitFileOk(&client);
            break;
        // send file ok ack
        case SEND_FILE_OK_ACK:
            curr_state = sendFileOkAck(&client);
            break;
        // wait for data packets
        case WAIT_FOR_DATA:
            curr_state = waitForData(&client);
            break;
        // handle in order data
        case IN_ORDER:
            curr_state = in_order(&client);
            break;
        // handle buffered data
        case BUFFER:
            curr_state = buffer(&client);
            break;
        // handle flushing data
        case FLUSHING:
            curr_state = flushing(&client);
            break;
        // teardown
        case TEARDOWN:
            curr_state = teardown(&client);
            break;
        // error exit
        case ERROR:
            curr_state = error_exit(&client);
            break;
        default:
            break;
        }
    }
    return;
}

/**
 * @brief Sets up the UDP socket to the server.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state setupSocket(session_t *client) {
    client->socketNum = setupUdpClientToServer(
        &client->serverAddr, client->serverName, client->portNumber);
    if (client->socketNum < 0) {
        fprintf(stderr, "Error setting up socket\n");
        return ERROR;
    } else {
        printf("Socket setup complete\n");
    }
    addToPollSet(client->socketNum);

    return SEND_FILENAME;
}

/**
 * @brief Sends the filename and buffer/window size to the server.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state sendFilename(session_t *client) {
    int pduLen = 0;
    int dataLen = strlen(client->fromFilename) + 8;
    char buffer[MAX_DATA_SIZE];
    uint8_t pduBuffer[MAX_PDU];
    uint32_t buf_size_net = htonl(client->bufSize);
    uint32_t win_size_net = htonl(client->winSize);

    // store window size, buffer size, and filename in buffer
    buffer[0] = '\0';
    memcpy(buffer, &buf_size_net, sizeof(uint32_t));
    memcpy(buffer + 4, &win_size_net, sizeof(uint32_t));
    memcpy(buffer + 8, client->fromFilename, strlen(client->fromFilename));

    // create the pdu
    pduLen = createPDU(pduBuffer, 0, SETUP_PACKET, (uint8_t *)buffer, dataLen);

    // send the filename
    sendtoErr(client->socketNum, pduBuffer, pduLen, 0,
              (struct sockaddr *)&client->serverAddr, client->serverAddrLen);

    return WAIT_FILE_OK;
}

/**
 * @brief Waits for the server to respond with a file ok packet.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state waitFileOk(session_t *client) {
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;
    state next_state = ERROR;
    int count = 0;

    // poll for incoming packet
    while (count < 10) {
        if (pollCall(1000) != client->socketNum) {
            fprintf(stderr, "Timeout waiting for file ok (attempt %d)\n",
                    count + 1);
            retryConnection(client, &count);
            continue;
        }

        // receive and validate packet
        if (recvAndVal(client, pduBuffer, &pduLen, &validateSetupPacket) < 0)
            return WAIT_FILE_OK;

        // check the flag and status
        uint8_t status = pduBuffer[7];
        if (status == FILENAME_OK) {
            next_state = SEND_FILE_OK_ACK;
        } else {
            fprintf(stderr, "Error: file '%s' not found\n",
                    client->fromFilename);
            next_state = ERROR;
        }
        break;
    }

    return next_state;
}

/**
 * @brief Sends the file ok ack to the server after opening the file.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state sendFileOkAck(session_t *client) {
    state next_state = WAIT_FOR_DATA;
    uint8_t status = FILENAME_OK_ACK;
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;

    // open the file
    if ((client->outputFile_fd =
             open(client->toFilename, O_CREAT | O_TRUNC | O_WRONLY,
                  OWNER_PERMISSION)) < 0) {
        fprintf(stderr, "Error on open of outputfile: %s\n",
                    client->fromFilename);
        return ERROR;
    } else {
        // create the pdu
        status = FILENAME_OK_ACK;
        pduLen = createPDU(pduBuffer, 0, FILE_OK_ACK_PACKET, &status, 1);

        // send the filename ok ack
        sendtoErr(client->socketNum, pduBuffer, pduLen, 0,
                  (struct sockaddr *)&client->serverAddr,
                  client->serverAddrLen);
    }

    return next_state;
}

/**
 * @brief Waits for data packets from the server.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state waitForData(session_t *client) {
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;

    // retry up to 10 times if no packet is received
    for (int retries = 0; retries < MAX_RETRIES; retries++) {
        if (pollCall(1000) != client->socketNum) {
            // timeout->send SREJ again for the missing packet
            fprintf(stderr, "Timeout waiting for data (attempt %d)\n",
                    retries + 1);
            send_SREJ(client, client->expSeqNum);
            continue;
        }

        // receive and validate packet
        if (recvAndVal(client, pduBuffer, &pduLen, &validateDataPacket) < 0)
            return WAIT_FOR_DATA;

        // parse sequence number
        uint32_t seq_num = extractSeqNum(pduBuffer);
        if (seq_num > client->topSeqNum) {
            client->topSeqNum = seq_num;
        }

        // decide on next state based on sequence number
        if (seq_num != client->expSeqNum) {
            bool is_last_data = (pduBuffer[6] == LAST_DATA_PACKET);
            buffer_store(&client->buffer, seq_num, pduBuffer + 7, pduLen - 7,
                         is_last_data);
            send_SREJ(client, client->expSeqNum);
            return BUFFER;
        } else {
            if (writeDataAndAck(client, pduBuffer + 7, pduLen - 7) < 0)
                return TEARDOWN;

            client->expSeqNum++;
            if (pduBuffer[6] == LAST_DATA_PACKET) {
                close(client->outputFile_fd);
                return TEARDOWN;
            }
            return IN_ORDER;
        }
    }

    return TEARDOWN;
}

/**
 * @brief Handles the in-order state where packets are received in order.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state in_order(session_t *client) {
    state next_state = IN_ORDER;
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;
    int flag = 0;

    for (int retries = 0; retries < MAX_RETRIES; retries++) {
        // poll for next packet
        if (pollCall(10000) != client->socketNum) {
            fprintf(stderr, "Timeout waiting for data (attempt %d)\n",
                    retries + 1);
            send_SREJ(client, client->expSeqNum);
            next_state = TEARDOWN;
            continue;
        }

        // receive and validate packet
        if (recvAndVal(client, pduBuffer, &pduLen, &validateDataPacket) < 0)
            return IN_ORDER;

        // parse seq num
        uint32_t seq_num = extractSeqNum(pduBuffer);
        if (seq_num > client->topSeqNum) {
            client->topSeqNum = seq_num;
        }

        // handle packet
        if (seq_num > client->expSeqNum) {
            bool is_last_data = (pduBuffer[6] == LAST_DATA_PACKET);
            buffer_store(&client->buffer, seq_num, pduBuffer + 7, pduLen - 7,
                         is_last_data);
            send_SREJ(client, client->expSeqNum);
            return BUFFER;
        }

        if (seq_num < client->expSeqNum) {
            // already received this packet, send RR
            send_RR(client, client->expSeqNum - 1);
            return IN_ORDER;
        }

        // in-order, write to file
        if (writeDataAndAck(client, pduBuffer + 7, pduLen - 7) < 0)
            return ERROR;

        client->expSeqNum++;
        flag = pduBuffer[6];
        if (flag == LAST_DATA_PACKET) {
            close(client->outputFile_fd);
            return TEARDOWN;
        }
    }

    return next_state;
}

/**
 * @brief Handles the buffering of out-of-order packets.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state buffer(session_t *client) {
    state next_state = BUFFER;
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;

    for (int retries = 0; retries < MAX_RETRIES; retries++) {
        // wait for new data
        if (pollCall(10000) != client->socketNum) {
            fprintf(stderr, "Timeout waiting for data (attempt %d)\n",
                    retries + 1);
            send_SREJ(client, client->expSeqNum);
            next_state = TEARDOWN;
            continue;
        }

        // receive and validate packet
        if (recvAndVal(client, pduBuffer, &pduLen, &validateDataPacket) < 0)
            return BUFFER;

        // parse sequence number
        uint32_t seq_num = extractSeqNum(pduBuffer);
        if (seq_num > client->topSeqNum) {
            client->topSeqNum = seq_num;
        }

        if (seq_num > client->expSeqNum) {
            // still missing packet, so buffer and wait
            bool is_last_data = (pduBuffer[6] == LAST_DATA_PACKET);
            buffer_store(&client->buffer, seq_num, pduBuffer + 7, pduLen - 7,
                         is_last_data);
            return BUFFER;
        } else if (seq_num < client->expSeqNum) {
            // already received this packet, send RR
            send_RR(client, client->expSeqNum - 1);
            return BUFFER;
        } else {
            // in-order packet we were waiting for just arrived!
            if (writeDataAndAck(client, pduBuffer + 7, pduLen - 7) < 0)
                return TEARDOWN;

            client->expSeqNum++;
            return FLUSHING;
        }
    }

    return next_state;
}

/**
 * @brief Handles the flushing of buffered packets to the output file.
 *
 * @param client
 * @return Returns the next state in the state machine.
 */
state flushing(session_t *client) {
    state next_state = FLUSHING;
    uint8_t dataBuf[MAX_DATA_SIZE];
    int dataLen = 0;
    bool is_last_data = false;

    // check if there are any buffered packets to flush
    while (buffer_peek(&client->buffer, client->expSeqNum)) {
        dataLen = buffer_get(&client->buffer, client->expSeqNum, dataBuf);
        if (dataLen < 0) {
            fprintf(stderr, "Error getting data from buffer for seq_num: %u\n",
                    client->expSeqNum);
            return ERROR;
        }

        // write data to file
        int bytesWritten = write(client->outputFile_fd, dataBuf, dataLen);
        if (bytesWritten < 0) {
            perror("Error writing to file");
            return ERROR;
        } else {
            is_last_data =
                bufferEntryIsLastPacket(&client->buffer, client->expSeqNum);
            buffer_consume(&client->buffer, client->expSeqNum);
            send_RR(client, client->expSeqNum);

            client->expSeqNum++;
        }
    }
    if (is_last_data) {
        next_state = TEARDOWN;
    } else if (client->expSeqNum < client->topSeqNum) {
        // if there are still packets to flush, go back to BUFFER state
        next_state = BUFFER;
    } else {
        // if no more packets to flush, go to IN ORDER state
        next_state = IN_ORDER;
    }

    return next_state;
}

/**
 * @brief Handles the teardown process, sending a teardown packet and cleaning
 * up resources.
 *
 * @param client
 * @return Returns DONE state to exit the state machine.
 */
state teardown(session_t *client) {
    // send the teardown packet
    sendTeardownPacket(client);

    // close the socket and free resources
    removeFromPollSet(client->socketNum);
    close(client->socketNum);
    buf_free(&client->buffer);
    printf("Teardown complete, exiting\n");
    return DONE;
}

/**
 * @brief Handles the error exit process, cleaning up resources and exiting.
 *
 * @param client
 * @return Returns DONE state to exit the state machine.
 */
state error_exit(session_t *client) {
    // close the socket and free resources
    removeFromPollSet(client->socketNum);
    close(client->socketNum);
    buf_free(&client->buffer);
    fprintf(stderr, "An error occurred, cleaning up and exiting\n");
    return DONE;
}

/**
 * @brief Retries the connection by closing the previous socket and setting up a
 * new one.
 *
 * @param client
 * @param count
 * @return void
 */
void retryConnection(session_t *client, int *count) {
    // close previous socket and reset
    removeFromPollSet(client->socketNum);
    close(client->socketNum);
    setupSocket(client);
    sendFilename(client);
    (*count)++;
}

/**
 * @brief Validates the setup packet received from the server.
 *
 * @param pduBuffer
 * @param pduLen
 * @return Returns 1 if valid, 0 if invalid.
 */
int validateSetupPacket(uint8_t *pduBuffer, int pduLen) {
    if (pduLen < 8)
        return 0; // minimum length for file ok packet
    uint8_t flag = pduBuffer[6];
    if (flag != FILE_OK_PACKET) {
        fprintf(stderr, "Error: expected setup packet, got flag %d\n", flag);
        return 0;
    }

    uint16_t checksum = in_cksum((unsigned short *)pduBuffer, pduLen);
    if (checksum != 0) {
        fprintf(stderr, "Corrupted PDU, dropped packet...\n");
        return 0;
    }
    return 1;
}

/**
 * @brief Validates the data packet received from the server.
 *
 * @param pduBuffer
 * @param pduLen
 * @return Returns 1 if valid, 0 if invalid.
 */
int validateDataPacket(uint8_t *pduBuffer, int pduLen) {
    if (pduLen < 7)
        return 0;
    uint8_t flag = pduBuffer[6];
    if (flag != DATA_PACKET && flag != LAST_DATA_PACKET &&
        flag != SREJ_RESEND_PACKET && flag != TIMEOUT_RESEND_PACKET) {
        fprintf(stderr, "Error: expected data packet, got flag %d\n", flag);
        return 0;
    }

    uint16_t checksum = in_cksum((unsigned short *)pduBuffer, pduLen);
    if (checksum != 0) {
        fprintf(stderr, "Corrupted PDU, dropping packet...\n");
        return 0;
    }
    return 1;
}

/**
 * @brief Extracts the sequence number from the PDU buffer.
 *
 * @param pduBuffer
 * @return Returns the sequence number as a uint32_t.
 */
uint32_t extractSeqNum(uint8_t *pduBuffer) {
    uint32_t net_seq;
    memcpy(&net_seq, pduBuffer, sizeof(uint32_t));
    return ntohl(net_seq);
}

/**
 * @brief Writes the data to the output file and sends an RR packet.
 *
 * @param client
 * @param data
 * @param len
 * @return Returns 0 on success, -1 on error.
 */
int writeDataAndAck(session_t *client, uint8_t *data, int len) {
    int bytesWritten = write(client->outputFile_fd, data, len);
    if (bytesWritten < 0) {
        perror("Error writing to file");
        return -1;
    }

    send_RR(client, client->expSeqNum);
    return 0;
}

/**
 * @brief Receives a packet and validates it using the provided validation
 * function.
 *
 * @param client
 * @param pduBuffer
 * @param pduLen
 * @param valfunc
 * @return Returns 0 on success, -1 on error.
 */
int recvAndVal(session_t *client, uint8_t *pduBuffer, int *pduLen,
               int (*valfunc)(uint8_t *, int)) {
    *pduLen = safeRecvfrom(client->socketNum, pduBuffer, MAX_PDU, 0,
                           (struct sockaddr *)&client->serverAddr,
                           &client->serverAddrLen);
    if (*pduLen < 0) {
        perror("Error receiving data");
        return -1;
    }

    if (!valfunc(pduBuffer, *pduLen))
        return -1;

    return 0;
}

/**
 * @brief Sends a teardown packet to the server to close the connection.
 *
 * @param client
 * @return Returns the number of bytes sent, or -1 on error.
 */
int sendTeardownPacket(session_t *client) {
    uint8_t pduBuffer[MAX_PDU];
    int pduLen = 0;

    // create the teardown packet
    pduLen = createPDU(pduBuffer, client->sendSeqNum, TEARDOWN_PACKET, NULL, 0);

    // send the teardown packet
    return sendtoErr(client->socketNum, pduBuffer, pduLen, 0,
                     (struct sockaddr *)&client->serverAddr,
                     client->serverAddrLen);
}

/**
 * @brief Sends a SREJ packet to the server for a specific sequence number.
 *
 * @param client
 * @param seq_num
 * @return void
 */
void send_SREJ(session_t *client, uint32_t seq_num) {
    uint8_t pduBuffer[MAX_PDU];
    uint8_t buffer[MAX_DATA_SIZE];
    int dataLen = sizeof(uint32_t);
    int pduLen = 0;

    // prepare the SREJ packet
    uint32_t seq_num_net = htonl(seq_num);
    memcpy(buffer, &seq_num_net, sizeof(uint32_t));

    // create the SREJ packet
    pduLen =
        createPDU(pduBuffer, client->sendSeqNum, SREJ_PACKET, buffer, dataLen);

    // send the SREJ packet
    sendtoErr(client->socketNum, pduBuffer, pduLen, 0,
              (struct sockaddr *)&client->serverAddr, client->serverAddrLen);
    client->sendSeqNum++; // increment send sequence number
}

/**
 * @brief Sends a RR packet to the server indicating readiness for the next
 * packet.
 *
 * @param client
 * @param seq_num
 * @return void
 */
void send_RR(session_t *client, uint32_t seq_num) {
    uint8_t pduBuffer[MAX_PDU];
    uint8_t buffer[MAX_DATA_SIZE];
    int dataLen = sizeof(uint32_t);
    int pduLen = 0;
    seq_num += 1; // receiver ready for next packet

    // prepare the RR packet
    uint32_t seq_num_net = htonl(seq_num);
    memcpy(buffer, &seq_num_net, sizeof(uint32_t));

    // create the RR packet
    pduLen =
        createPDU(pduBuffer, client->sendSeqNum, RR_PACKET, buffer, dataLen);

    // send the RR packet
    sendtoErr(client->socketNum, pduBuffer, pduLen, 0,
              (struct sockaddr *)&client->serverAddr, client->serverAddrLen);
    client->sendSeqNum++; // increment send sequence number
}

/**
 * @brief Checks the command line arguments for validity.
 *
 * @param argc
 * @param argv
 * @return Returns the port number to connect to.
 */
int checkArgs(int argc, char *argv[]) {
    int portNumber = 0;

    /* check command line arguments  */
    if (argc != 8) {
        printf("usage: %s from-filename to-filename window-size buffer-size "
               "error-rate remote-machine remote-port \n",
               argv[0]);
        exit(1);
    }

    portNumber = atoi(argv[7]);

    float error_rate = atof(argv[1]);
    if (error_rate < 0 || error_rate > 1) {
        fprintf(stderr, "Error rate must be between 0 and 1\n");
        exit(EXIT_FAILURE);
    }

    // check buffer size
    uint32_t bufSize = atoi(argv[3]);
    if (bufSize > MAX_DATA_SIZE) {
        fprintf(stderr, "Buffer size must be less than %d\n", MAX_DATA_SIZE);
        exit(EXIT_FAILURE);
    }

    // check filename lengths
    char *fromFilename = argv[1];
    char *toFilename = argv[2];
    if (strlen(fromFilename) > MAX_FILENAME) {
        fprintf(stderr, "Error: filename too long: %s\n", fromFilename);
        exit(EXIT_FAILURE);
    }
    if (strlen(toFilename) > MAX_FILENAME) {
        fprintf(stderr, "Error: filename too long: %s\n", toFilename);
        exit(EXIT_FAILURE);
    }

    return portNumber;
}
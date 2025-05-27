/* Server side - UDP Code				    */
/* By Hugh Smith	4/1/2017	*/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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

// struct to hold session info
typedef struct {
    // network info
    int socketNum;
    struct sockaddr_in6 addr;
    int addrLen;

    // file info
    char *filename;
    int32_t dataFile_fd;

    // window info
    window_t win;
    uint32_t winSize;
    uint32_t bufSize;

    // pdu info
    uint8_t pduBuffer[MAX_PDU];
    int pduLen;
    int dataRead; // total data read from file

    // protocol info
    uint32_t seq_num;        // current sequence number
    uint32_t lastDataSeqNum; // last sequence number sent for data
} session_t;

// state machine for server
typedef enum {
    // setup state
    OPEN_FILE,
    WAIT_FILE_OK_ACK,

    // data states
    DATA_TRANSFER,

    // teardown state
    WAIT_FOR_TEARDOWN,
    TEARDOWN,

    // done and error state
    DONE,
    ERROR
} state;

// state machine functions
state openFile(session_t *server);
state waitFileOkAck(session_t *server);
state dataTransfer(session_t *server);
state waitForTeardown(session_t *server);
state teardown(session_t *server);
state errorexit(session_t *server);

// connection processing functions
void processServer(int socketNum);
int processClient(session_t *server);
void handleChildSession(session_t *server);
off_t get_file_size(int fd);
int sendDataPacket(session_t *server, int flag, uint8_t *data, int len);
int receiveControlPacket(session_t *server);
int resendLowestUnacked(session_t *server);
int isValidSetupPacket(uint8_t *pduBuffer, int pduLen);
int handleWindowOpen(session_t *server, bool *eof_sent);
int handleWindowClosed(session_t *server);
int processRR_SREJ(session_t *server);
int checkArgs(int argc, char *argv[]);
void handleZombies(int sig);

/** * @brief Main function for the UDP server.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return Returns 0 on success, or -1 on error.
 */
int main(int argc, char *argv[]) {
    int socketNum = 0;
    int portNumber = 0;

    // check command line arguments
    portNumber = checkArgs(argc, argv);

    // initialize send error
    float error_rate = atof(argv[1]);
    sendErr_init(error_rate, DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);

    // setup and handle server connections
    socketNum = udpServerSetup(portNumber);

    // setup the poll set
    setupPollSet();
    addToPollSet(socketNum);

    // process the server
    processServer(socketNum);
    close(socketNum);

    return 0;
}

/**
 * @brief Processes the server by accepting client connections and handling
 * sessions.
 *
 * @param socketNum The socket number for the server.
 * @return void
 */
void processServer(int socketNum) {
    pid_t pid;
    session_t server = {
        .socketNum = socketNum,
        .addrLen = sizeof(server.addr),
        .winSize = 0,
        .bufSize = 0,
        .pduLen = 0,
        .dataRead = 0,
        .seq_num = 0,
        .lastDataSeqNum = 0,
    };

    // clean up for forked children
    signal(SIGCHLD, handleZombies);

    while (1) {
        // wait for a new client connection
        server.pduLen =
            safeRecvfrom(socketNum, server.pduBuffer, MAX_PDU, 0,
                         (struct sockaddr *)&server.addr, &server.addrLen);

        if (server.pduLen > 0 &&
            isValidSetupPacket(server.pduBuffer, server.pduLen)) {
            if ((pid = fork()) < 0) {
                // fork failed
                perror("fork failed");
                exit(EXIT_FAILURE);
            }
            if (pid == 0) {
                // child process
                handleChildSession(&server);
                exit(EXIT_SUCCESS);
            }
        }
    }
}

/**
 * @brief Processes the client session by entering the state machine.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns the socket number of the server.
 */
int processClient(session_t *server) {
    state curr_state = OPEN_FILE;

    // enter state machine
    while (curr_state != DONE) {
        switch (curr_state) {
        // handle file opening
        case OPEN_FILE:
            curr_state = openFile(server);
            break;
        // wait for file ok ack
        case WAIT_FILE_OK_ACK:
            curr_state = waitFileOkAck(server);
            break;
        // send data
        case DATA_TRANSFER:
            curr_state = dataTransfer(server);
            break;
        case WAIT_FOR_TEARDOWN:
            curr_state = waitForTeardown(server);
            break;
        // teardown
        case TEARDOWN:
            curr_state = teardown(server);
            break;
        // error state
        case ERROR:
            curr_state = errorexit(server);
            break;
        default:
            break;
        }
    }

    return server->socketNum;
}

/**
 * @brief Opens the file specified in the setup packet and sends an
 * acknowledgment.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns the next state in the state machine.
 */
state openFile(session_t *server) {
    char filename[MAX_FILENAME];
    state next_state = WAIT_FILE_OK_ACK;
    uint8_t status = FILENAME_BAD;
    uint32_t buf_size_net, win_size_net;

    // get buffer size, window size, and filename from setup pdu
    memcpy(&buf_size_net, server->pduBuffer + 7, sizeof(uint32_t));
    memcpy(&win_size_net, server->pduBuffer + 11, sizeof(uint32_t));
    memcpy(filename, server->pduBuffer + 15, server->pduLen - 15);
    server->bufSize = ntohl(buf_size_net);
    server->winSize = ntohl(win_size_net);
    filename[server->pduLen - 15] = '\0';

    // open the file and send according status
    if ((server->dataFile_fd = open(filename, O_RDONLY)) < 0) {
        server->pduLen =
            createPDU(server->pduBuffer, 0, FILE_OK_PACKET, &status, 1);
        sendtoErr(server->socketNum, server->pduBuffer, server->pduLen, 0,
                  (struct sockaddr *)&server->addr, server->addrLen);
        fprintf(stderr, "Error opening file: %s\n", filename);
        next_state = ERROR; // exit on error
    } else {
        status = FILENAME_OK;
        server->pduLen =
            createPDU(server->pduBuffer, 0, FILE_OK_PACKET, &status, 1);
        sendtoErr(server->socketNum, server->pduBuffer, server->pduLen, 0,
                  (struct sockaddr *)&server->addr, server->addrLen);
        printf("File opened: %s\n", filename);
    }

    return next_state;
}

/**
 * @brief Waits for the file ok acknowledgment from the client.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns the next state in the state machine.
 */
state waitFileOkAck(session_t *server) {
    state next_state = WAIT_FILE_OK_ACK;
    int flag = 0;
    uint8_t status = 0;

    // wait for file ok ack
    if (pollCall(10000) != server->socketNum) {
        fprintf(stderr, "Timeout waiting for file ok ack\n");
        return ERROR;
    }

    // receive the file ok ack
    server->pduLen =
        safeRecvfrom(server->socketNum, server->pduBuffer, MAX_PDU, 0,
                     (struct sockaddr *)&server->addr, &server->addrLen);
    if (server->pduLen <= 0) {
        fprintf(stderr, "Failed to receive file ok ack\n");
        return ERROR;
    }

    // validate PDU
    flag = server->pduBuffer[6];
    if (flag != FILE_OK_ACK_PACKET) {
        fprintf(stderr, "Error: expected FILE_OK_ACK_PACKET (got flag %d)\n",
                flag);
        return ERROR;
    }

    // validate checksum
    uint16_t checksum =
        in_cksum((unsigned short *)server->pduBuffer, server->pduLen);
    if (checksum != 0) {
        fprintf(stderr, "Corrupted PDU, dropping packet\n");
        return next_state;
    }

    // check the status
    memcpy(&status, server->pduBuffer + 7, sizeof(uint8_t));
    if (status == FILENAME_OK_ACK) {
        next_state = DATA_TRANSFER;
    } else {
        fprintf(stderr, "Error opening file on receiver side\n");
        next_state = ERROR;
    }

    return next_state;
}

/**
 * @brief Handles the data transfer state by sending data packets and managing
 * the window.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns the next state in the state machine.
 */
state dataTransfer(session_t *server) {
    window_init(&server->win, server->winSize);
    bool eof_sent = false;
    int ret = 0;

    // handle data while the window is not empty and not all data has been sent
    while (!eof_sent || !window_is_empty(&server->win)) {
        while (!eof_sent && window_is_open(&server->win)) {
            ret = handleWindowOpen(server, &eof_sent);
            if (ret < 0) {
                fprintf(stderr, "Error handling window open\n");
                return ERROR; // exit on error
            }
        }

        // window is closed here
        ret = handleWindowClosed(server);
        if (ret < 0) {
            fprintf(stderr, "Error handling window closed\n");
            return ERROR; // exit on error
        }
    }
    return WAIT_FOR_TEARDOWN;
}

/**
 * @brief Waits for a teardown packet from the client to close the connection.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns the next state in the state machine.
 */
state waitForTeardown(session_t *server) {
    int flag = 0;
    for (int retries = 0; retries < MAX_RETRIES; retries++) {
        if (pollCall(1000) == server->socketNum) {
            int len = safeRecvfrom(server->socketNum, server->pduBuffer,
                                   MAX_PDU, 0, (struct sockaddr *)&server->addr,
                                   &server->addrLen);
            flag = server->pduBuffer[6];
            if (len > 0 && flag == TEARDOWN_PACKET) {
                return TEARDOWN;
            }
        }
    }

    return TEARDOWN;
}

/**
 * @brief Handles the teardown process by closing the file and freeing
 * resources.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns DONE state to exit the state machine.
 */
state teardown(session_t *server) {
    // close and free resources
    close(server->dataFile_fd);
    removeFromPollSet(server->socketNum);
    close(server->socketNum);
    buf_free(&server->win.circ_buf);
    printf("Teardown complete, closing connection\n");
    return DONE;
}

/**
 * @brief Handles the error exit process by cleaning up resources and exiting.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns DONE state to exit the state machine.
 */
state errorexit(session_t *server) {
    close(server->dataFile_fd);
    removeFromPollSet(server->socketNum);
    close(server->socketNum);
    buf_free(&server->win.circ_buf);
    fprintf(stderr, "error occured, cleaning up and exiting\n");
    return DONE;
}

/**
 * @brief Handles the child session by setting up a new socket and processing
 * the client.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return void
 */
void handleChildSession(session_t *server) {
    close(server->socketNum);
    removeFromPollSet(server->socketNum);

    server->socketNum = udpServerSetup(server->addr.sin6_port);
    addToPollSet(server->socketNum);
    printf("child process started with pid: %d, socketNum: %d\n", getpid(),
           server->socketNum);

    processClient(server);
}

/**
 * @brief Gets the size of the file associated with the given file descriptor.
 *
 * @param fd The file descriptor of the file.
 * @return Returns the size of the file in bytes, or -1 on error.
 */
off_t get_file_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) == 0) {
        return st.st_size;
    } else {
        perror("fstat");
        return -1; // error
    }
}

/**
 * @brief Sends a data packet to the client.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @param flag The flag indicating the type of data packet.
 * @param data Pointer to the data to be sent.
 * @param len The length of the data to be sent.
 * @return Returns 0 on success, or -1 on error.
 */
int sendDataPacket(session_t *server, int flag, uint8_t *data, int len) {
    server->pduLen =
        createPDU(server->pduBuffer, server->seq_num, flag, data, len);
    sendtoErr(server->socketNum, server->pduBuffer, server->pduLen, 0,
              (struct sockaddr *)&server->addr, server->addrLen);
    return 0;
}

/**
 * @brief Receives a control packet (RR or SREJ) from the client and processes
 * it.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns 0 on success, or -1 on error.
 */
int receiveControlPacket(session_t *server) {
    server->pduLen =
        safeRecvfrom(server->socketNum, server->pduBuffer, MAX_PDU, 0,
                     (struct sockaddr *)&server->addr, &server->addrLen);
    if (server->pduLen <= 0)
        return -1;

    // reset the resend count of the lowest since packets are coming through
    buffer_entry_t *entry = window_get_entry(&server->win, server->win.lower);
    if (entry) {
        entry->resend_count = 0;
    }

    // validate PDU
    uint16_t checksum =
        in_cksum((unsigned short *)server->pduBuffer, server->pduLen);
    if (checksum != 0) {
        fprintf(stderr, "Corrupted PDU, dropping packet\n");
        return 0;
    }

    return processRR_SREJ(server);
}

/**
 * @brief Handles the window open state by reading data from the file and
 * sending data packets.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @param eof_sent Pointer to a boolean indicating if EOF has been sent.
 * @return Returns 0 on success, or -1 on error.
 */
int handleWindowOpen(session_t *server, bool *eof_sent) {
    int dataLen, file_size;
    uint8_t data[MAX_DATA_SIZE];
    int flag = DATA_PACKET;
    bool is_last_data = false;

    // read from file and determine if EOF
    if ((file_size = (int)get_file_size(server->dataFile_fd)) < 0) {
        perror("Error getting file size");
        return -1;
    }

    dataLen = read(server->dataFile_fd, data, server->bufSize);
    if (dataLen < 0) {
        perror("Error reading from file");
        return -1;
    }
    server->dataRead += dataLen;
    if ((server->dataRead == file_size || dataLen < server->bufSize) &&
        !*eof_sent) {
        flag = LAST_DATA_PACKET;
        is_last_data = true;
    }

    // send data packet and update window
    if (!*eof_sent) {
        if (sendDataPacket(server, flag, data, dataLen) < 0)
            return -1;
        if (window_add(&server->win, server->seq_num, data, dataLen,
                       is_last_data) < 0) {
            fprintf(stderr, "Window full, cannot add new packet\n");
            return 0;
        }
        server->seq_num++; // increment sequence number for next packet
        if (flag == LAST_DATA_PACKET)
            *eof_sent = true;
    }

    // process RR or SREJ if available
    if (pollCall(0) > 0 && receiveControlPacket(server) < 0) {
        fprintf(stderr, "Error processing RR/SREJ\n");
        return -1;
    }

    return 0;
}

/**
 * @brief Resends the lowest unacknowledged packet in the window.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns 0 on success, or -1 on error.
 */
int resendLowestUnacked(session_t *server) {
    int sendFlag = TIMEOUT_RESEND_PACKET;
    buffer_entry_t *entry = window_resend(&server->win, server->win.lower);
    if (!entry)
        return -1;
    if (entry->is_last_data) {
        sendFlag = LAST_DATA_PACKET;
    }

    server->pduLen = createPDU(server->pduBuffer, entry->seq_num, sendFlag,
                               entry->data, entry->len);
    sendtoErr(server->socketNum, server->pduBuffer, server->pduLen, 0,
              (struct sockaddr *)&server->addr, server->addrLen);
    entry->resend_count++;

    return 0;
}

/**
 * @brief Handles the window closed state by waiting for RR/SREJ or resending
 * packets on timeout.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns 0 on success, or -1 on error.
 */
int handleWindowClosed(session_t *server) {
    // wait for RR/SREJ or resend on timeout
    if (pollCall(1000) > 0) {
        if (receiveControlPacket(server) < 0) {
            fprintf(stderr, "Error processing RR/SREJ\n");
            return -1;
        }
    } else {
        if (resendLowestUnacked(server) < 0) {
            fprintf(
                stderr,
                "Packet resend failed 10 times and not receiving packets\n");
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Processes the RR or SREJ packet received from the client.
 *
 * @param server Pointer to the session_t structure containing server
 * information.
 * @return Returns 0 on success, or -1 on error.
 */
int processRR_SREJ(session_t *server) {
    int flag = server->pduBuffer[6];

    // Check if the packet is a RR or SREJ
    if (flag == RR_PACKET) {
        uint32_t rr_value = 0;
        memcpy(&rr_value, server->pduBuffer + 7, sizeof(uint32_t));
        rr_value = ntohl(rr_value);
        int ret = window_ack(&server->win, rr_value);
        if (ret < 0) {
            fprintf(stderr, "Error acknowledging packet %u\n", rr_value);
            return -1;
        }
    } else if (flag == SREJ_PACKET) {
        int sendFlag = SREJ_RESEND_PACKET;
        uint32_t srej_value = 0;
        memcpy(&srej_value, server->pduBuffer + 7, sizeof(uint32_t));
        srej_value = ntohl(srej_value);
        buffer_entry_t *entry = window_resend(&server->win, srej_value);
        if (entry) {
            entry->resend_count = 0; // reset resend count for this entry
            if (entry->is_last_data) {
                sendFlag = LAST_DATA_PACKET;
            }

            // resend the packet with the specified sequence number
            server->pduLen = createPDU(server->pduBuffer, entry->seq_num,
                                       sendFlag, entry->data, entry->len);
            sendtoErr(server->socketNum, server->pduBuffer, server->pduLen, 0,
                      (struct sockaddr *)&server->addr, server->addrLen);
            entry->resend_count++;
        } else {
            fprintf(
                stderr,
                "Packet resend failed 10 times and not receiving packets\n");
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Validates the setup packet received from the client.
 *
 * @param pduBuffer Pointer to the PDU buffer containing the setup packet.
 * @param pduLen Length of the PDU buffer.
 * @return Returns 1 if valid, 0 if invalid.
 */
int isValidSetupPacket(uint8_t *pduBuffer, int pduLen) {
    if (pduBuffer[6] != SETUP_PACKET) {
        fprintf(stderr, "Error: expected setup packet (got %d)\n",
                pduBuffer[6]);
        return 0;
    }

    uint16_t checksum = in_cksum((unsigned short *)pduBuffer, pduLen);
    if (checksum != 0) {
        fprintf(stderr, "Corrupted PDU, dropping packet\n");
        return 0;
    }

    return 1;
}

/**
 * @brief Handles zombie processes by reaping them.
 *
 * @param sig Signal number (not used).
 * @return void
 */
void handleZombies(int sig) {
    int status = 0;
    while (waitpid(-1, &status, WNOHANG) > 0)
        ;
}

/**
 * @brief Checks command line arguments for error rate and optional port number.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return Returns the port number if provided, or 0 if not.
 */
int checkArgs(int argc, char *argv[]) {
    // Checks args and returns port number
    int portNumber = 0;

    if (argc > 3) {
        fprintf(stderr, "Usage %s error-rate [optional port number]\n",
                argv[0]);
        exit(-1);
    }

    if (argc == 3) {
        portNumber = atoi(argv[2]);
        // check error rate
        float error_rate = atof(argv[1]);
        if (error_rate < 0 || error_rate > 1) {
            fprintf(stderr, "Error rate must be between 0 and 1\n");
            exit(EXIT_FAILURE);
        }
    }

    return portNumber;
}

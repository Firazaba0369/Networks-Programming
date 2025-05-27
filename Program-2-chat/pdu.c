#include "pdu.h"

int sendPDU(int clientSocket, uint8_t *dataBuffer, int lengthOfData) {
    uint16_t pdu_length = lengthOfData + 2; // data +2 byte header

    // convert to network byte order
    uint16_t net_length = htons(pdu_length);
    uint8_t full_data_buf[pdu_length];

    // copy the length and data in the full data buffer
    memcpy(full_data_buf, &net_length, 2);
    memcpy(full_data_buf + 2, dataBuffer, lengthOfData);

    // send the data to the server
    int ret = safeSend(clientSocket, full_data_buf, pdu_length, 0);
    if (ret != pdu_length) {
        perror("sendPDU: failed to send data");
        return -1;
    }

    // return the number of bytes sent (excluding the header)
    return ret - 2;
}

int recvPDU(int socketNumber, uint8_t *dataBuffer, int bufferSize) {
    uint16_t pdu_length = 0;     // lenngth of the pdu
    uint16_t net_length = 0;     // length of the pdu in network byte order
    uint16_t payload_length = 0; // length of the payload
    uint8_t header_buf[2];       // buffer to store the header
    int ret = 0;                 // return value

    // receive the header first
    ret = safeRecv(socketNumber, header_buf, 2, MSG_WAITALL);
    if (ret == 0) {
        return ret; // connection closed
    }
    if (ret != 2) {
        perror("recvPDU: failed to receive header");
        return -1;
    }

    // convert the pdu_length to host byte order
    memcpy(&net_length, header_buf, 2);
    pdu_length = ntohs(net_length);

    // Get the payload length
    payload_length = pdu_length - 2;

    // check if the pdu length is valid
    if (payload_length > bufferSize) {
        fprintf(stderr,
                "recvPDU: payload (%d bytes) exceeds buffer size (%d bytes)\n",
                payload_length, bufferSize);
        exit(1);
    }

    // recieve the data
    ret = safeRecv(socketNumber, dataBuffer, payload_length, MSG_WAITALL);
    if (ret != payload_length) {
        perror("recvPDU: failed to receive full payload");
        return -1;
    }

    // return the number of bytes received
    return ret;
}
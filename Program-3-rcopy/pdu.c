#include "pdu.h"

int createPDU(uint8_t *pdubuffer, uint32_t sequenceNumber, uint8_t flag, uint8_t *payload, int payloadlen){
    int pduLength = 4+2+1+payloadlen;
    uint16_t checksum = 0;
    uint32_t seqNumNet = htonl(sequenceNumber);

    //build the PDU
    memcpy(pdubuffer, &seqNumNet, sizeof(uint32_t));
    memcpy(pdubuffer+4, &checksum, sizeof(uint16_t));
    memcpy(pdubuffer+6, &flag, sizeof(uint8_t));
    memcpy(pdubuffer+7, payload, payloadlen);

    //calculate checksum and update that field in the PDU
    checksum = in_cksum((unsigned short *)pdubuffer, pduLength);
    memcpy(pdubuffer+4, &checksum, sizeof(uint16_t));
    
    return pduLength;
}

void printPDU(uint8_t *aPDU, int pduLength){
    uint32_t seqNumNet = 0;
    uint32_t sequenceNumber = 0;
    uint8_t flag = 0;
    char payload[MAX_PAYLOAD_SIZE + 1] = {0};
    int payloadlen = pduLength - 7;

    //check the PDU 
    uint16_t checksum = in_cksum((unsigned short *)aPDU, pduLength);
    if(checksum != 0){
        fprintf(stderr, "Corrupted PDU\n");
        return;
    }

    //extract the fields from the PDU
    memcpy(&seqNumNet, aPDU, sizeof(uint32_t));
    sequenceNumber = ntohl(seqNumNet); 
    flag = aPDU[6];
    memcpy(payload, aPDU+7, pduLength-7);
    payload[pduLength-7] = '\0';

    //print the fields
    printf("Sequence Number: %u\n", sequenceNumber);
    printf("flag: %u\n", flag);
    printf("Payload: %s\n", payload);
    printf("Payload Length: %d\n", payloadlen);
    
    return;
}
#ifndef PDU_H
#define PDU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "checksum.h"

#define MAX_PAYLOAD_SIZE 1400
#define MAX_PDU 1407

int createPDU(uint8_t *pdubuffer, uint32_t sequenceNumber, uint8_t flag, uint8_t *payload, int payloadlen);
void printPDU(uint8_t *aPDU, int pduLength);

#endif // PDU_H
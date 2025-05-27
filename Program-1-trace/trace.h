#ifndef TRACE_H
#define TRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>     
#include <netinet/ether.h>  
#include "checksum.h"

#define ETHERTYPE_IP 0x0800 //IPv4
#define ETHERTYPE_ARP 0x0806 //ARP
#define PROTOCOL_ICMP 0x01 //ICMP
#define PROTOCOL_TCP 0x06 //TCP
#define PROTOCOL_UDP 0x11 //UDP

typedef struct eth_hdr{
    struct ether_addr dest_mac; //destination MAC address
    struct ether_addr src_mac; //source MAC address
    uint16_t ethertype; //EtherType field
} eth_hdr;

typedef struct ip_hdr{
    uint8_t ihl; //IP version and header length
    uint16_t total_length; //total length of the packet
    uint8_t ttl; //time to live
    uint8_t protocol; //protocol type (ICMP, TCP, UDP)
    uint16_t checksum; //header checksum
    struct in_addr src_ip; //source IP address
    struct in_addr dest_ip; //destination IP address
} ip_hdr;

typedef struct arp_hdr{
    uint16_t opcode; //operation code (request/reply)
    struct ether_addr src_mac; //source MAC address
    struct in_addr src_ip; //source IP address
    struct ether_addr target_mac; //destination MAC address
    struct in_addr target_ip; //destination IP address
} arp_hdr;

typedef struct tcp_hdr{
    uint16_t src_port; //source port
    uint16_t dest_port; //destination port
    uint32_t seq_num; //sequence number
    uint32_t ack_num; //acknowledgment number
    uint8_t data_offset; //data offset
    uint8_t SYN_flag; //SYN flag
    uint8_t RST_flag; //RST flag
    uint8_t FIN_flag; //FIN flag
    uint8_t ACK_flag; //ACK flag
    uint16_t window_size; //window size
    uint16_t checksum; //header checksum
} tcp_hdr;

typedef struct icmp_hdr{
    uint8_t type; //ICMP type
} icmp_hdr;

typedef struct udp_hdr{
    uint16_t src_port; //source port
    uint16_t dest_port; //destination port
} udp_hdr;

typedef struct pseudo_hdr {
    struct in_addr source_address;   // Source IP address
    struct in_addr dest_address;     // Destination IP address
    uint8_t placeholder;       // 8 bits set to zero
    uint8_t protocol;          // Protocol type 
    uint16_t tcp_length;       // TCP Length (length of the TCP segment)
} pseudo_hdr;

void ethernet(const u_char *packet, eth_hdr *ethernet_header);
void print_ethernet(eth_hdr *ethernet_header);
void ip(const u_char *packet, ip_hdr *ip_header);
void print_ip(const u_char *packet, ip_hdr *ip_header);
void arp(const u_char *packet, arp_hdr *arp_header);
void print_arp(arp_hdr *arp_header);
void tcp(const u_char *packet, ip_hdr *ip_header);
void print_tcp(const u_char *packet, tcp_hdr *tcp_header, ip_hdr *ip_header);
unsigned short tcp_checksum(const u_char *packet, ip_hdr *ip_header);
void icmp(const u_char *packet);
void print_icmp(icmp_hdr *icmp_header);
void udp(const u_char *packet);
void print_udp(udp_hdr *udp_header);
void trace(pcap_t *packet_reader);

#endif
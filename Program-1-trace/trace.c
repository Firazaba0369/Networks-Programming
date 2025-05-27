#include "trace.h"

void ethernet(const u_char *packet, eth_hdr *ethernet_header) {
    // extract ethernet header information
    memcpy(&ethernet_header->dest_mac, packet, 6);
    memcpy(&ethernet_header->src_mac, packet + 6, 6);
    memcpy(&ethernet_header->ethertype, packet + 12, 2);
    ethernet_header->ethertype =
        ntohs(ethernet_header->ethertype); // convert to host byte order

    // print the ethernet header information
    print_ethernet(ethernet_header);
    return;
}

void print_ethernet(eth_hdr *ethernet_header) {
    // print the ethernet header information
    fprintf(stdout, "\n\tEthernet Header\n");
    fprintf(stdout, "\t\tDest MAC: %s\n",
            ether_ntoa(&ethernet_header->dest_mac));
    fprintf(stdout, "\t\tSource MAC: %s\n",
            ether_ntoa(&ethernet_header->src_mac));
    if (ethernet_header->ethertype == ETHERTYPE_IP) {
        fprintf(stdout, "\t\tType: IP\n");
    } else if (ethernet_header->ethertype == ETHERTYPE_ARP) {
        fprintf(stdout, "\t\tType: ARP\n");
    } else {
        fprintf(stdout, "\t\tType: Unknown (0x%04x)\n",
                ethernet_header->ethertype);
    }
    return;
}

void ip(const u_char *packet, ip_hdr *ip_header) {
    // store the IP header information in struct(convert 16 and 32-bit values to
    // host byte order)
    memcpy(&ip_header->ihl, packet, 1);
    ip_header->ihl =
        ((ip_header->ihl) & 0x0F) * 4; // extract anc convert to bytes
    memcpy(&ip_header->total_length, packet + 2, 2);
    ip_header->total_length = ntohs(ip_header->total_length);
    memcpy(&ip_header->ttl, packet + 8, 1);
    memcpy(&ip_header->protocol, packet + 9, 1);
    memcpy(&ip_header->checksum, packet + 10, 2);
    ip_header->checksum = ntohs(ip_header->checksum);
    memcpy(&ip_header->src_ip, packet + 12, 4);
    memcpy(&ip_header->dest_ip, packet + 16, 4);

    // print the IP header information
    print_ip(packet, ip_header);
    return;
}

void print_ip(const u_char *packet, ip_hdr *ip_header) {
    // print the IP header information
    fprintf(stdout, "\n\tIP Header\n");
    fprintf(stdout, "\t\tIP PDU Len: %d\n", ip_header->total_length);
    fprintf(stdout, "\t\tHeader Len (bytes): %d\n", ip_header->ihl);
    fprintf(stdout, "\t\tTTL: %d\n", ip_header->ttl);
    if (ip_header->protocol == PROTOCOL_TCP) {
        fprintf(stdout, "\t\tProtocol: TCP\n");
    } else if (ip_header->protocol == PROTOCOL_ICMP) {
        fprintf(stdout, "\t\tProtocol: ICMP\n");
    } else if (ip_header->protocol == PROTOCOL_UDP) {
        fprintf(stdout, "\t\tProtocol: UDP\n");
    } else {
        fprintf(stdout, "\t\tProtocol: Unknown\n");
    }

    // use the checksum function to verify the checksum value in the IP
    // header and print accordingly
    if (in_cksum((unsigned short *)packet, ip_header->ihl) != 0) {
        fprintf(stdout, "\t\tChecksum: Incorrect (0x%04x)\n",
                ip_header->checksum);
    } else {
        fprintf(stdout, "\t\tChecksum: Correct (0x%04x)\n",
                ip_header->checksum);
    }
    fprintf(stdout, "\t\tSender IP: %s\n", inet_ntoa(ip_header->src_ip));
    fprintf(stdout, "\t\tDest IP: %s\n", inet_ntoa(ip_header->dest_ip));
    return;
}

void arp(const u_char *packet, arp_hdr *arp_header) {
    // extract ethernet header information (convert 16 and 32-bit values to host
    // byte order)
    memcpy(&arp_header->opcode, packet + 6, 2);
    arp_header->opcode = ntohs(arp_header->opcode);
    memcpy(&arp_header->src_mac, packet + 8, 6);
    memcpy(&arp_header->src_ip, packet + 14, 4);
    memcpy(&arp_header->target_mac, packet + 18, 6);
    memcpy(&arp_header->target_ip, packet + 24, 4);

    // print the ethernet header information
    print_arp(arp_header);
    return;
}

void print_arp(arp_hdr *arp_header) {
    // print the ARP header information
    fprintf(stdout, "\n\tARP header\n");

    // check opcode for request/reply and print accordingly
    if (arp_header->opcode == 1) {
        fprintf(stdout, "\t\tOpcode: Request\n");
    } else if (arp_header->opcode == 2) {
        fprintf(stdout, "\t\tOpcode: Reply\n");
    } else {
        fprintf(stdout, "\t\tOpcode: Unknown (%d)\n", arp_header->opcode);
    }
    fprintf(stdout, "\t\tSender MAC: %s\n", ether_ntoa(&arp_header->src_mac));
    fprintf(stdout, "\t\tSender IP: %s\n", inet_ntoa(arp_header->src_ip));
    fprintf(stdout, "\t\tTarget MAC: %s\n",
            ether_ntoa(&arp_header->target_mac));
    fprintf(stdout, "\t\tTarget IP: %s\n", inet_ntoa(arp_header->target_ip));
    return;
}

void tcp(const u_char *packet, ip_hdr *ip_header) {
    packet = packet + sizeof(eth_hdr) + ip_header->ihl; // skip the IP header
    tcp_hdr tcp_header;

    // extract TCP header information (convert 16 and 32-bit values to host byte
    // order)
    memcpy(&tcp_header.src_port, packet, 2);
    tcp_header.src_port = ntohs(tcp_header.src_port);
    memcpy(&tcp_header.dest_port, packet + 2, 2);
    tcp_header.dest_port = ntohs(tcp_header.dest_port);
    memcpy(&tcp_header.seq_num, packet + 4, 4);
    tcp_header.seq_num = ntohl(tcp_header.seq_num);
    memcpy(&tcp_header.ack_num, packet + 8, 4);
    tcp_header.ack_num = ntohl(tcp_header.ack_num);
    memcpy(&tcp_header.data_offset, packet + 12, 1);
    tcp_header.data_offset = (tcp_header.data_offset >> 4);

    // get individual flags from the TCP header
    uint8_t flags;
    memcpy(&flags, packet + 13, 1);
    tcp_header.SYN_flag = (flags & 0x02);
    tcp_header.RST_flag = (flags & 0x04);
    tcp_header.FIN_flag = (flags & 0x01);
    tcp_header.ACK_flag = (flags & 0x10);
    memcpy(&tcp_header.window_size, packet + 14, 2);
    tcp_header.window_size = ntohs(tcp_header.window_size);
    memcpy(&tcp_header.checksum, packet + 16, 2);
    tcp_header.checksum = ntohs(tcp_header.checksum);

    // print the TCP header information
    print_tcp(packet, &tcp_header, ip_header);
}

void print_tcp(const u_char *packet, tcp_hdr *tcp_header, ip_hdr *ip_header) {
    unsigned long tcp_seg_len =
        ip_header->total_length - ip_header->ihl; // TCP segment length in bytes

    // print the TCP header information
    fprintf(stdout, "\n\tTCP Header\n");
    fprintf(stdout, "\t\tSegment Length: %ld\n", tcp_seg_len);

    // print the source and destination ports
    if (tcp_header->src_port == 80) {
        fprintf(stdout, "\t\tSource Port:  HTTP\n");
    } else {
        fprintf(stdout, "\t\tSource Port:  %d\n", tcp_header->src_port);
    }
    if (tcp_header->dest_port == 80) {
        fprintf(stdout, "\t\tDest Port:  HTTP\n");
    } else {
        fprintf(stdout, "\t\tDest Port:  %d\n", tcp_header->dest_port);
    }

    // print the sequence, acknowledgment numbers, and data offset
    fprintf(stdout, "\t\tSequence Number: %u\n", tcp_header->seq_num);
    fprintf(stdout, "\t\tACK Number: %u\n", tcp_header->ack_num);
    fprintf(stdout, "\t\tData Offset (bytes): %d\n",
            tcp_header->data_offset * 4); // data offset in bytes

    // print the TCP flags
    tcp_header->SYN_flag ? fprintf(stdout, "\t\tSYN Flag: Yes\n")
                         : fprintf(stdout, "\t\tSYN Flag: No\n");
    tcp_header->RST_flag ? fprintf(stdout, "\t\tRST Flag: Yes\n")
                         : fprintf(stdout, "\t\tRST Flag: No\n");
    tcp_header->FIN_flag ? fprintf(stdout, "\t\tFIN Flag: Yes\n")
                         : fprintf(stdout, "\t\tFIN Flag: No\n");
    tcp_header->ACK_flag ? fprintf(stdout, "\t\tACK Flag: Yes\n")
                         : fprintf(stdout, "\t\tACK Flag: No\n");
    fprintf(stdout, "\t\tWindow Size: %d\n", tcp_header->window_size);

    // calculate checksum
    unsigned short checksum = tcp_checksum(packet, ip_header);
    if (checksum != 0) {
        fprintf(stdout, "\t\tChecksum: Incorrect (0x%04x)\n",
                tcp_header->checksum);
    } else {
        fprintf(stdout, "\t\tChecksum: Correct (0x%04x)\n",
                tcp_header->checksum);
    }

    return;
}

unsigned short tcp_checksum(const u_char *packet, ip_hdr *ip_header) {
    unsigned long tcp_seg_len = ip_header->total_length - ip_header->ihl;
    // build pseudo header for TCP checksum calculation
    pseudo_hdr psh;
    memcpy(&psh.source_address, &ip_header->src_ip, sizeof(ip_header->src_ip));
    memcpy(&psh.dest_address, &ip_header->dest_ip, sizeof(ip_header->dest_ip));
    psh.placeholder = 0;
    psh.protocol = ip_header->protocol;
    psh.tcp_length = htons(tcp_seg_len);

    // allocate a static buffer to hold the pseudo header and TCP data
    unsigned char pseudogram[sizeof(pseudo_hdr) + tcp_seg_len];

    // copy the pseudo header to the buffer
    memcpy(pseudogram, &psh, sizeof(pseudo_hdr));

    // copy the TCP segment to the buffer
    memcpy(pseudogram + sizeof(pseudo_hdr), packet, tcp_seg_len);

    // calculate checksum
    unsigned short checksum =
        in_cksum((unsigned short *)pseudogram, sizeof(pseudogram));
    return checksum;
}

void icmp(const u_char *packet) {
    icmp_hdr icmp_header;

    // extract ICMP header information (convert 16 and 32-bit values to host
    // byte order)
    memcpy(&icmp_header.type, packet, 1);

    // print the ICMP header information
    print_icmp(&icmp_header);
    return;
}

void print_icmp(icmp_hdr *icmp_header) {
    // print the ICMP header information
    fprintf(stdout, "\n\tICMP Header\n");
    if (icmp_header->type == 8) {
        printf("\t\tType: Request\n");
    } else if (icmp_header->type == 0) {
        printf("\t\tType: Reply\n");
    } else {
        printf("\t\tType: %d\n", icmp_header->type);
    }
    return;
}

void udp(const u_char *packet) {
    udp_hdr udp_header;
    // extract UDP header information (convert 16 and 32-bit values to host byte
    // order)
    memcpy(&udp_header.src_port, packet, 2);
    udp_header.src_port = ntohs(udp_header.src_port);
    memcpy(&udp_header.dest_port, packet + 2, 2);
    udp_header.dest_port = ntohs(udp_header.dest_port);

    // print the UDP header information
    print_udp(&udp_header);
    return;
}

void print_udp(udp_hdr *udp_header) {
    // print the UDP header information
    fprintf(stdout, "\n\tUDP Header\n");

    // print the source and destination ports
    if (udp_header->src_port == 53) {
        fprintf(stdout, "\t\tSource Port:  DNS\n");
    } else {
        fprintf(stdout, "\t\tSource Port:  %d\n", udp_header->src_port);
    }

    if (udp_header->dest_port == 53) {
        fprintf(stdout, "\t\tDest Port:  DNS\n");
    } else {
        fprintf(stdout, "\t\tDest Port:  %d\n", udp_header->dest_port);
    }

    return;
}

void trace(pcap_t *packet_reader) {
    // initialize the ethernet and IP header structs
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_num = 1;
    int ret;

    // read packets from the pcap file in a loop
    while ((ret = pcap_next_ex(packet_reader, &header, &packet)) > 0) {
        fprintf(stdout, "\nPacket number: %d  Packet Len: %d\n", packet_num++,
                header->len);

        // call the ethernet function to process the packet
        eth_hdr ethernet_header;
        ethernet(packet, &ethernet_header);

        ip_hdr ip_header;
        arp_hdr arp_hdr;
        // check the EtherType field to determine the type of packet
        if (ethernet_header.ethertype == ETHERTYPE_IP) {
            // call the ip function to process the IP packet
            ip(packet + sizeof(eth_hdr), &ip_header);

            // check the protocol field to determine the type of IP packet
            if (ip_header.protocol == PROTOCOL_TCP) {
                // call the tcp function to process the TCP packet
                tcp(packet, &ip_header);
            } else if (ip_header.protocol == PROTOCOL_ICMP) {
                // call the icmp function to process the ICMP packet
                icmp(packet + sizeof(eth_hdr) + ip_header.ihl);
            } else if (ip_header.protocol == PROTOCOL_UDP) {
                // call the udp function to process the UDP packet
                udp(packet + sizeof(eth_hdr) + ip_header.ihl);
            } else {
                continue;
            }
        } else if (ethernet_header.ethertype == ETHERTYPE_ARP) {
            // call the arp function to process the ARP packet
            arp(packet + sizeof(eth_hdr), &arp_hdr);
        } else {
            fprintf(stdout, "Unknown EtherType: %04x\n",
                    ethernet_header.ethertype);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        // check if the user provided a pcap file as an argument
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // open the pcap file for reading
    char *filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *packet_reader = pcap_open_offline(filename, errbuf);
    if (packet_reader == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // call the trace function to process the packets in the pcap file
    trace(packet_reader);

    // close the pcap file
    pcap_close(packet_reader);
}
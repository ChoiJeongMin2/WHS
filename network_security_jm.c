#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    unsigned char  ether_dhost[6]; /* destination host address */
    unsigned char  ether_shost[6]; /* source host address */
    unsigned short ether_type;     /* protocol type (IP, ARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char      iph_ihl:4,  // IP header length
                       iph_ver:4;  // IP version
    unsigned char      iph_tos;    // Type of service
    unsigned short int iph_len;    // Total length (header + data)
    unsigned short int iph_ident;  // Identification
    unsigned short int iph_flag:3, // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;       // Time to Live
    unsigned char      iph_protocol;  // Protocol typeS
    unsigned short int iph_chksum;    // IP checksum
    struct in_addr     iph_sourceip;  // Source IP address
    struct in_addr     iph_destip;    // Destination IP address
};

/* TCP Header */
struct tcpheader {
    unsigned short tcp_sport;   /* source port */
    unsigned short tcp_dport;   /* destination port */
    unsigned int   tcp_seq;     /* sequence number */
    unsigned int   tcp_ack;     /* acknowledgement number */
    unsigned char  tcp_offx2;   /* data offset (upper 4 bits) + reserved bits */
    unsigned char  tcp_flags;   /* TCP flags */
    unsigned short tcp_win;     /* window size */
    unsigned short tcp_sum;     /* checksum */
    unsigned short tcp_urp;     /* urgent pointer */
};

/* Macro to extract TCP header length in 32-bit words */
#define TH_OFF(th) (((th)->tcp_offx2 & 0xF0) >> 4)

/* Callback function invoked by pcap_loop() */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header,
                const unsigned char *packet)
{
    /* 1. Parse Ethernet header */
    struct ethheader *eth = (struct ethheader *)packet;

    // 0x0800은 이더넷 헤더에서 IP 프로토콜을 의미
    if (ntohs(eth->ether_type) == 0x0800) {
        /* 2. Parse IP header */
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        // 프로토콜이 TCP(6)인지 확인
        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;

            /* 3. Parse TCP header */
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = TH_OFF(tcp) * 4;

            /* ----- Ethernet Header Info ----- */
            printf("Ethernet Header:\n");
            printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            /* ----- IP Header Info ----- */
            printf("IP Header:\n");
            printf("  Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("  Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            /* ----- TCP Header Info ----- */
            printf("TCP Header:\n");
            printf("  Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("  Dst Port: %d\n", ntohs(tcp->tcp_dport));

            /* 4. Calculate payload offset and length */
            int total_ip_len = ntohs(ip->iph_len); // IP 총 길이(헤더+데이터)
            int payload_length = total_ip_len - (ip_header_len + tcp_header_len);

            /* 5. Extract and print payload */
            const unsigned char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            printf("Payload (%d bytes):\n", payload_length);
            if (payload_length > 0) {
                // 출력 길이 제한 (예: 최대 100바이트)
                int print_len = (payload_length > 500) ? 500 : payload_length;
                // ASCII로 가정하고 출력
                printf("%.*s\n", print_len, payload);
            } else {
                printf("No payload\n");
            }
            printf("\n-----------------------------\n");
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    /* 
     * "tcp port 80"로 필터 설정:
     * HTTP 트래픽(포트 80)만 캡처 
     */
    char filter_exp[] = "tcp port 80";

    bpf_u_int32 net;
    bpf_u_int32 mask;

    /* 1. Open live pcap session on NIC (예: "enp0s3") */
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device enp0s3: %s\n", errbuf);
        return 2;
    }

    /* 2. Get network number and mask for the device */
    if (pcap_lookupnet("enp0s3", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device enp0s3: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    /* 3. Compile filter expression into BPF pseudo-code */
    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    /* 4. Set the filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    /* 5. Capture packets (infinite loop) */
    pcap_loop(handle, -1, got_packet, NULL);

    /* 6. Close the handle */
    pcap_close(handle);
    return 0;
}

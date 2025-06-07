#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <stdint.h>

#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 1024

// Packing major and minor into uint16_t
#define MAKE_VERSION(major, minor) (((uint16_t)(major) << 8) | ((uint16_t)(minor)))

// Extracting major and minor
#define GET_MAJOR(version) (((version) >> 8) & 0xFF)
#define GET_MINOR(version) ((version) & 0xFF)

// Checking if version matches specific major and minor
#define IS_VERSION(version, major, minor) \
    (GET_MAJOR(version) == (major) && GET_MINOR(version) == (minor))

const char *base_name(const char *path) {
    const char *last_slash = strrchr(path, '/');
    return last_slash != NULL ? last_slash + 1 : path;
}

typedef struct {
	uint16_t packet_id;
	uint16_t version;
} __attribute__ ((packed)) packet_header_t;

typedef enum {
	REQ_LOGIN      = 0x0001,
} req_packet_t;

typedef enum {
	RES_LOGIN      = 0x8001, // 0x8000 = 32768
} res_packet_t;

typedef enum {
	SUCCESS = 0,
	INCORRECT 
} code_t;


typedef struct {
	char username[255];
	char password[255];
} login_info;

typedef struct {
	int status_code;
	char session_id[33];
} __attribute__ ((packed)) login_result_t;


typedef enum {
    STATUS_OK = 0,
    
    // Login-specific errors
    STATUS_LOGIN_FAILED = -1,
    STATUS_LOGIN_USER_NOT_FOUND = -2,
    STATUS_LOGIN_WRONG_PASSWORD = -3,

    // Protocol errors
    STATUS_PROTOCOL_MISMATCH = -100,
    STATUS_INVALID_RESPONSE = -101,
    STATUS_UNEXPECTED_PACKET_ID = -102,

    // System errors
    STATUS_NETWORK_ERROR = -200,
    STATUS_TIMEOUT = -201,
} status_code_t;

result_t api_request_login_v1(int sock, const char *username, const char *password) {
	uint8_t user_len = strlen(username);
	uint8_t pass_len = strlen(password);
	
	packet_header_t meta;
	login_result_t res;
	
	meta.packet_id = REQ_LOGIN;
	meta.version = MAKE_VERSION(1, 0);
	
	// write headers
	write(sock, &meta, sizeof(meta));
	// write username length 1 byte
	write(sock, &user_len, 1);
	// write username byte
	write(sock, username, user_len);
	// write password length 1 byte
	write(sock, &pass_len, 1);
	// write password byte 
	write(sock, password, pass_len);
	
	packet_header_t r;
	
	read(sock, &r, sizeof(r));
	
	if (r.packet_id != RES_LOGIN) {
		res.status_code = STATUS_UNEXPECTED_PACKET_ID;
		return res;
	}
	
	read(sock.
	
	/*
	if (r.packet_id == RES_LOGIN) {
		printf("login response!\n");
		printf("packet_id: %04X\n", r.packet_id);
		printf("version: %u.%u\n", GET_MAJOR(r.version), GET_MINOR(r.version));
	}*/
}

const char *get_error_msg(code_t code) {
	
	
}

int connect_server(const char *ip, const unsigned int port) {
	struct sockaddr_in serv_addr;
	
	// Create socket
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sock < 0) {
		perror("Socket creation error");
		return -1;
	}
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	
	// Convert IPv4 address from text to binary
	if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
		perror("Invalid address or Address not supported");
		return -1;
	}
	
	// Connect to server
	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("Connection failed");
		return -1;
	}
	
	return sock;
}

typedef int conn_t;

int main(int argc, const char *argv[]) {
	conn_t conn = connect_server(SERVER_IP, SERVER_PORT);
	
	if (conn == -1) {
		fprintf(stderr, "Failed to connect server!\n");
		return EXIT_FAILURE;
	}
	
	login_result_t res = api_request_login_v1(conn, "admin", "admin@1234");
	
	if (res.status_code == STATUS_OK) {
		printf("token: %s\n", res.session_id);
	}
	
	close(conn);
	return 0;
}
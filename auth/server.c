#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>

#define PORT 8888
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
	REQ_REGISTER    = 0x0002,
	DELETE_FILE      = 0x0003,
	RENAME_FILE      = 0x0004,
	CHECKSUM_FILE    = 0x0005,
} request_packet_t;

typedef enum {
	RES_LOGIN = 0x8001,
	RES_REGISTER = 0x8002,
} response_packet_t;


uint8_t read_uint8(int sock) {
	uint8_t temp = 0;
	read(sock, &temp, 1);
	return temp;
}

typedef struct {
	char username[256];
	char password[256];
} __attribute ((packed)) login_info;

/*
bool get_header_info(int sock, packet_header_t h) {
	return read(sock, &h, sizeof(h)) == sizeof(h);
}
*/

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

bool login_handler(int sock) {
	packet_header_t h;
	
	h.packet_id = RES_LOGIN;
	h.version = MAKE_VERSION(1, 1);
	
	uint8_t username_len = 0;
	uint8_t password_len = 0;
	char username[256];
	char password[256];
	
	read(sock, &username_len, 1);
	read(sock, username, username_len);
	
	read(sock, &password_len, 1);
	read(sock, password, password_len);
	
	write(sock, &h, sizeof(h));
	
	if (memcmp(username, "admin", 5) == 0) {
		if (memcmp(password, "admin@1234", 10) == 0) {
			return true;
		} else {
			printf("[INFO] Password incorrect!\n");
		}
	} else {
		printf("[INFO] User not found!\n");
	}
	
	return false;
}


typedef struct {
    uint8_t status_code;
    uint8_t session_token[16];
} login_response_t;

int main() {
	int server_fd, conn_id;
	struct sockaddr_in address;
	uint8_t buffer[BUFFER_SIZE];
	login_info info;
	
	char path[] = "files/";
	
	mkdir(path, 0775);
	
	// Create socket
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (server_fd == 0) {
		perror("Socket failed");
		exit(EXIT_FAILURE);
	}
	
	// Bind socket to port
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;  // Bind to all interfaces
	address.sin_port = htons(PORT);
	
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}
	
	// Listen for connections
	if (listen(server_fd, 3) < 0) {
		perror("Listen");
		exit(EXIT_FAILURE);
	}
	
	printf("Server listening on port %d...\n", PORT);
	
	socklen_t addrlen = sizeof(address);
	packet_header_t h;
	
	struct timeval timeout;
	timeout.tv_sec = 5;      // seconds
	timeout.tv_usec = 0;     // microseconds

	
	while (1) {
		conn_id = accept(server_fd, (struct sockaddr *)&address, &addrlen);
		
		if (conn_id < 0) {
			fprintf(stderr, "Failed to accept connection!\n");
			continue;
		}
		
		int ret = setsockopt(conn_id, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		
		if (ret < 0) {
			perror("setsockopt SO_RCVTIMEO failed");
		}
		
		printf("connection accept!\n");
		
		ssize_t n = 0;
		
		while (1) {
			n = recv(conn_id, &h, sizeof(h), 0);
			
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					printf("Receive timed out: no data received within 5 seconds.\n");
				} else {
					perror("recv error");
				}
				break;
			} else if (n == 0) {
				printf("Connection closed by peer.\n");
				break;
			}
			
			
			if (h.packet_id == REQ_LOGIN) {
				printf("[INFO] Login request!\n");
				if (login_handler(conn_id)) {
					printf("[SUCCESS] Login successfully!\n");
				} else {
					printf("[ERROR] Login failed!\n");
				}
			} else if (h.packet_id == REQ_REGISTER){
				printf("[INFO] Register request!\n");
				
				
			} else {
				printf("[WARNING] unknown method!\n");
				printf("packet_id: %04X\n", h.packet_id);
				printf("version: %u.%u\n", GET_MAJOR(h.version), GET_MINOR(h.version));
				close(conn_id);
				break;
			}
			
			close(conn_id);
			break;
		}
		
		close(conn_id);
	}
	
	close(server_fd);
	
	return 0;
}
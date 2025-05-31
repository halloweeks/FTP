#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>

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
} __attribute__ ((packed)) header;

typedef enum {
	UPLOAD_FILE      = 0x0001,
	DOWNLOAD_FILE    = 0x0002,
	DELETE_FILE      = 0x0003,
	RENAME_FILE      = 0x0004,
	CHECKSUM_FILE    = 0x0005,
} packet_t;

int main() {
	int server_fd, client_socket;
	struct sockaddr_in address;
	uint8_t buffer[BUFFER_SIZE];
	
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
	
	uint32_t len = 0;
	header h;
	
	uint8_t filename_length = 0;
	char filename[255];
	uint64_t filesize = 0;
	
	char temp[1024];
	
	int fout = 0;
	uint32_t remains_size = 0;
	uint32_t total_size = 0;
	size_t bytesToRead = 0;
	uint32_t bytesRead = 0;
	
	while (1) {
		client_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
		
		if (client_socket < 0) {
			fprintf(stderr, "Failed to accept connection!\n");
			continue;
		}
		
		printf("connection accept!\n");
		
		while (1) {
			if (read(client_socket, &h, sizeof(h)) != sizeof(h)) {
				fprintf(stderr, "Failed to read!\n");
				close(client_socket);
				break;
			}
			
			printf("packet_id: %04X\n", h.packet_id);
			printf("version: %u.%u\n", GET_MAJOR(h.version), GET_MINOR(h.version));
			
			if (h.packet_id == UPLOAD_FILE && IS_VERSION(h.version, 1, 1)) {
				// read total filename length 
				read(client_socket, &filename_length, 1);
				// read file name 
				read(client_socket, filename, filename_length);
				filename[filename_length + 1] = '\0';
				// read total file size
				read(client_socket, &filesize, 8);
				
				strncpy(temp, path, strlen(path));
				strncat(temp, filename, filename_length + 1);
				
				total_size = filesize;
				
				printf("filename: %s\n", filename);
				printf("filesize: %lu\n", filesize);
				
				printf("valid data!\n");
				
				fout = open(temp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
				
				while (total_size > 0) {
					bytesToRead = filesize < BUFFER_SIZE ? filesize : BUFFER_SIZE;
					
					bytesRead = read(client_socket, buffer, bytesToRead);
					
					write(fout, buffer, bytesRead);
					
					total_size -= bytesRead;
				}
				
				close(fout);
				memset(temp, 0, sizeof(temp));
				close(client_socket);
				break;
			} else {
				fprintf(stderr, "No valid data!\n");
				close(client_socket);
				break;
			}
			
		}
		
		close(client_socket);
	}
	
	close(server_fd);
	
	return 0;
}
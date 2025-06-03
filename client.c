#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <stdint.h>

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

/*
typedef struct {
	uint16_t packet_id;
	uint16_t version;
} __attribute__ ((packed)) packet_header_t;

typedef enum {
	REQ_UPLOAD_FILE      = 0x0001,
	REQ_DOWNLOAD_FILE    = 0x0002,
	REQ_DELETE_FILE      = 0x0003,
	REQ_RENAME_FILE      = 0x0004,
	REQ_CHECKSUM_FILE    = 0x0005,
} req_packet_t;

typedef enum {
	RES_UPLOAD_FILE      = 0x8001, // 0x8000 = 32768
	RES_DOWNLOAD_FILE    = 0x8002,
	RES_DELETE_FILE      = 0x8003,
	RES_RENAME_FILE      = 0x8004,
	RES_CHECKSUM_FILE    = 0x8005,
} res_packet_t;

char email[] = "test@example.com";
char pass[] = "1234";

result_t res = api_login_v1(email, pass);

if (res.status_code == LOGIN_SUCCESS) {

}
*/

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

int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage ./%s <filepath>\n", base_name(argv[0]));
		return EXIT_FAILURE;
	}
	
	if (access(argv[1], F_OK) == -1) {
		fprintf(stderr, "Input %s file does not exist.\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	struct stat st;
	
	if (stat(argv[1], &st) != 0) {
		fprintf(stderr, "Something went wrong!\n");
		return EXIT_FAILURE;
	}
	
	int fd = open(argv[1], O_RDONLY);
    
    if (fd == -1) {
    	fprintf(stderr, "Unable to open file\n");
		return EXIT_FAILURE;
    }
	
	printf("size: %lu\n", st.st_size);
	
    struct sockaddr_in serv_addr;
    uint8_t buffer[BUFFER_SIZE];

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sock < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 address from text to binary
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }
    
    // version 1.1
    uint8_t major = 1;
    uint8_t minor = 1;
    
    header h;
    h.packet_id = UPLOAD_FILE;
    h.version = MAKE_VERSION(1, 1); // (major << 8) | minor;
    
    uint8_t filename_length = strlen(argv[1]);
    uint8_t filename[255];
    memcpy(filename, argv[1], filename_length);
    uint64_t filesize = st.st_size;
    
    uint32_t read_byte = 0;
    
    write(sock, &h, sizeof(h));
    write(sock, &filename_length, 1);
    write(sock, filename, filename_length);
    write(sock, &filesize, 8);
    
    while ((read_byte = read(fd, buffer, BUFFER_SIZE)) > 0) {
    	write(sock, buffer, read_byte);
    }
    
    if (read_byte == 0) {
    	printf("file processing done!\n");
    } else {
    	printf("file processing error!\n");
    }
    /*
    char *hello = "Hello from client!";
    send(sock, hello, strlen(hello), 0);
    printf("Message sent\n");
    */
    /*
    read(sock, buffer, BUFFER_SIZE);
    printf("Server says: %s\n", buffer);
    */
    /*
    uint8_t major = (version >> 8) & 0xFF;
uint8_t minor = version & 0xFF;
*/
    close(fd);
    close(sock);
    return 0;
}

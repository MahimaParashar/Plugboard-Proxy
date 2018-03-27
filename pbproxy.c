//
// Created by Mahima Parashar on 11/11/17.
//
//
// Created by Mahima Parashar on 11/8/17.
//


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>


#define BUF_SIZE 4096

typedef enum {false, true} boolean;


typedef struct {
    int sockfd;
    int sshfd;
    struct sockaddr_in sshaddr;
    unsigned char *key;
} connection_thread;

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
    * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
    return 0;
}

unsigned char* readFile(char* fname){
    unsigned char *key;
    key = malloc(sizeof(unsigned char)*16);
    FILE *keyFile = fopen(fname,"r");
    if(keyFile == NULL){
        fprintf(stderr,"Error reading key file.");
    }
    if((fread(key, 1, 16, keyFile) < 16)){
        fprintf(stderr, "Key is less than 16 bytes.");
    }
    return key;
}
// Client Mode
void client(struct sockaddr_in servaddr, int dst_port, unsigned char *keyFile){
    int n,proxyClientSocket,rc, on = 1;
    unsigned char buffer[BUF_SIZE];
    bzero(buffer, BUF_SIZE);

    if ((proxyClientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "\n Socket creation error \n");
        return;
    }

    //connecting to proxy-server side
    if (connect(proxyClientSocket, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        fprintf(stderr, "Connection failed!\n");
        return;
    }

    rc = setsockopt(proxyClientSocket, SOL_SOCKET,  SO_REUSEADDR,
                    (char *)&on, sizeof(on));
    if (rc < 0)
    {
        perror("setsockopt() failed");
        close(proxyClientSocket);
        exit(-1);
    }


    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

    int flags = fcntl(proxyClientSocket, F_GETFL);
    if (flags == -1) {
        fprintf(stderr, "read sockfd flag error!\n");
        close(proxyClientSocket);
    }
    fcntl(proxyClientSocket, F_SETFL, flags | O_NONBLOCK);



    struct ctr_state state;
    AES_KEY aes_key;
    unsigned char iv[8];

    if (AES_set_encrypt_key(keyFile, 128, &aes_key) < 0) {
        fprintf(stderr, "Could not set encryption key.");
        exit(1);
    }


    while(1){
        while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
//            fprintf(stderr, "Read from STDIN: %d\n", n);
            char *temp = (char *) malloc(n+8);
            unsigned char encryptedData[n];

            if(!RAND_bytes(iv, 8))
            {
                fprintf(stderr, "Could not create random bytes.");
                exit(1);
            }
            memcpy(temp, iv, 8);
            int size = n+8;
            init_ctr(&state, iv);
            AES_ctr128_encrypt(buffer, encryptedData, (size_t)n, &aes_key, state.ivec, state.ecount, &state.num);
            memcpy(temp + 8, encryptedData, n);

            int r;
            if ((r = write(proxyClientSocket, temp, (size_t)size)) < 0) {
                fprintf(stderr, "Write to socket failed");
            }
//            fprintf(stderr, "Write to buffer: %d\n", n);
            free(temp);
            if (n < BUF_SIZE)
                break;
        }
        while ((n = read(proxyClientSocket, buffer, BUF_SIZE)) > 0) {
            unsigned char decryptedData[n - 8];

            if (n < 8) {
                fprintf(stderr, "Incorrect packet length. \n");
                close(proxyClientSocket);
                return;
            }
            memcpy(iv, buffer, 8);
            int size = n-8;
            init_ctr(&state, iv);
            AES_ctr128_encrypt(buffer + 8, decryptedData, (size_t)size, &aes_key, state.ivec, state.ecount, &state.num);

            int r;
            if ((r = write(STDOUT_FILENO, decryptedData, (size_t)size)) < 0) {
                fprintf(stderr, "Write to STDOUT failed");
            }
            if (n < BUF_SIZE)
                break;
        }
    }
}

void* server_thread(void *ptr){
    int n, rc, on = 1;
    int rc2;
    int ssh_fd, sshDone = 0;
    unsigned char buffer[BUF_SIZE];

    bzero(buffer, BUF_SIZE);
    if (!ptr) pthread_exit(0);
    printf("New thread started\n");
    connection_thread *connection = (connection_thread *)ptr;
    int newSocketfd = connection->sockfd;
    struct sockaddr_in ssh_addr = connection->sshaddr;
    unsigned char *key = connection->key;

    ssh_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (connect(ssh_fd, (struct sockaddr *)&ssh_addr, sizeof(ssh_addr)) < 0) {
        printf("Could not connect to ssh.\n");
        pthread_exit(0);
    } else {
        printf("Connection to ssh established.\n");
    }

    rc = setsockopt(ssh_fd, SOL_SOCKET,  SO_REUSEADDR,
                    (char *)&on, sizeof(on));
    if (rc < 0)
    {
        perror("setsockopt() failed");
        close(ssh_fd);
        exit(-1);
    }


    rc2 = setsockopt(newSocketfd, SOL_SOCKET,  SO_REUSEADDR,
                    (char *)&on, sizeof(on));
    if (rc2 < 0)
    {
        perror("setsockopt() failed");
        close(ssh_fd);
        exit(-1);
    }



    rc = ioctl(ssh_fd, FIONBIO, (char *)&on);
    if (rc < 0)
    {
        perror("ioctl() failed");
        close(ssh_fd);
        exit(-1);
    }

    rc2 = ioctl(newSocketfd, FIONBIO, (char *)&on);
    if (rc2 < 0)
    {
        perror("ioctl() failed");
        close(newSocketfd);
        exit(-1);
    }

    struct ctr_state state;
    AES_KEY aes_key;
    unsigned char iv[8];

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }


    while(1){
        while ((n = read(newSocketfd, buffer, BUF_SIZE)) > 0) {
//          fprintf(stderr, "CS: %d", n);
            if (n < 8) {
                printf("Incorrect packet length. \n");
                pthread_exit(0);
            }
            memcpy(iv, buffer, 8);
            unsigned char decryption[n-8];
            init_ctr(&state, iv);
            AES_ctr128_encrypt(buffer+8, decryption, (size_t)n-8, &aes_key, state.ivec, state.ecount, &state.num);
            //printf("%.*s\n", n, buffer);

            int r;
            if ((r = write(ssh_fd, decryption, n-8)) < 0){
                fprintf(stderr, "Write to ssh failed");
            }
//          fprintf(stderr, "Bytes written: %d", r);
            if (n < BUF_SIZE)
                break;
        }

        int x;
        while((x = read(ssh_fd, buffer, BUF_SIZE)) >= 0){
//          fprintf(stderr, "SS: %d", x);
            if (x > 0) {
                if (!RAND_bytes(iv, 8)) {
                    fprintf(stderr, "Error generating random bytes.\n");
                    close(ssh_fd);
                    exit(1);
                }
                int size = x+8;
                char *temp = (char *) malloc(size);
                memcpy(temp, iv, 8);
                unsigned char encryption[x];
                init_ctr(&state, iv);
                AES_ctr128_encrypt(buffer, encryption, (size_t)x, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(temp + 8, encryption, x);

                usleep(900);


                int r;
                if ((r = write(newSocketfd, temp, (size_t)size)) < 0) {
                    fprintf(stderr, "Write to 2222 failed");
                    close(newSocketfd);
                }
                free(temp);
            }
            if (!sshDone && !x){
                sshDone = 1;
            }

            if (x < BUF_SIZE)
                break;
        }

        if (sshDone)
            break;
    }

    printf("Closing connections. Exiting thread!\n");
    close(newSocketfd);
    close(ssh_fd);
    free(connection);
    pthread_exit(0);
}

void server(struct sockaddr_in sshaddr, struct sockaddr_in servaddr, unsigned  char *keyFile) {
//    fprintf(stderr, "Server adrres: should be 2222 %d\n Ssh port should be 22: %d\n", (int)servaddr.sin_port, (int)sshaddr.sin_port);
    int listenSocket, sshSocket, n, newsocketfd, rc, on = 1;
    char buffer[BUF_SIZE];
    connection_thread *connection;
    pthread_t thread;

    bzero(buffer, BUF_SIZE);

    if ((listenSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    rc = setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR,
                    (char *) &on, sizeof(on));
    if (rc < 0) {
        perror("setsockopt() failed");
        close(listenSocket);
        exit(-1);
    }
    if (bind(listenSocket, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(listenSocket, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    int client_len;
    client_len = sizeof(client_addr);

    while (newsocketfd = (accept(listenSocket, (struct sockaddr *) &client_addr, (socklen_t *) &(client_len)))) {
        fprintf(stderr, "Connection request received. ");
        connection = (connection_thread *) malloc(sizeof(connection_thread));
        connection->sockfd = newsocketfd;
        connection->sshaddr = sshaddr;
        connection->key = keyFile;
        if (newsocketfd > 0) {
            pthread_create(&thread, 0, server_thread, (void *) connection);
            pthread_detach(thread);
        } else {
            perror("Error in accepting connection");
            free(connection);
        }
    }
}


    int main(int argc, char *argv[]) {
        int c = 0;
        char *str_listen_port = NULL;
        boolean server_mode = false;
        unsigned char *key_file = NULL;
        char *str_dst = NULL;
        char *str_dst_port = NULL;


        while ((c = getopt(argc, argv, "k:l:")) != -1) {
            switch (c) {
                case 'k':
                    key_file = readFile(optarg);
                    break;
                case 'l':
                    str_listen_port = optarg;
                    server_mode = true;
                    break;
                case '?':
                    // when user didn't specify argument
                    if (optopt == 'l') {
                        fprintf(stderr, "Listing port not specified.");
                        return 0;
                    } else if (optopt == 'k') {
                        fprintf(stderr, "Key file not specified");
                        return 0;
                    } else {
                        fprintf(stderr, "Unknown argument.\n");
                        return 0;
                    }
                default:
                    fprintf(stderr, "Default case.\n");
                    return 0;
            }
        }
        // get destination ip and port
        if (optind == argc - 2) {
            str_dst = argv[optind];
            str_dst_port = argv[optind + 1];
        } else {
            fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
            return 0;
        }

        if (key_file == NULL) {
            fprintf(stderr, "Key file not specified!\n");
            return 0;
        }

        fprintf(stderr, "\n\tInitializing pbproxy using following parameters:\n\
		server mode: %s\n\
		listening port: %s\n\
		key file: %s\n\
		destination addr: %s\n\
		destination port: %s\n\n\n"\
, server_mode ? "true" : "false", str_listen_port, key_file, \
        str_dst, str_dst_port);

        //fprintf(stderr, "Server adrres: should be 2222 %s\n Ssh port should be 22: %s\n", str_listen_port, str_dst_port);

        struct sockaddr_in servaddr, sshaddr, proxyaddr;
        memset(&servaddr, '0', sizeof(servaddr));
        memset(&sshaddr, '0', sizeof(sshaddr));
        memset(&proxyaddr, '0', sizeof(proxyaddr));
        struct hostent *nlp_host;
        if ((nlp_host = gethostbyname(str_dst)) == 0) {
            fprintf(stderr, "Resolve Error!\n");
            return 0;
        }


        //client mode
        if (server_mode == false) {
            int dst_port = (int) strtol(str_dst_port, NULL, 10);

            proxyaddr.sin_family = AF_INET;
            proxyaddr.sin_port = htons(dst_port);
            proxyaddr.sin_addr.s_addr = ((struct in_addr *) (nlp_host->h_addr))->s_addr;

            client(proxyaddr, dst_port, key_file);

        } // server mode
        else {
            //int listenSocket;
            int listen_port = (int) strtol(str_listen_port, NULL, 10);
            int dst_port = (int) strtol(str_dst_port, NULL, 10);

            servaddr.sin_family = AF_INET;
            servaddr.sin_addr.s_addr = INADDR_ANY;
            servaddr.sin_port = htons(listen_port); //2222

            sshaddr.sin_family = AF_INET;
            sshaddr.sin_port = htons(dst_port); //22
            sshaddr.sin_addr.s_addr = ((struct in_addr *) (nlp_host->h_addr))->s_addr;
            //fprintf(stderr, "Server adrres: should be 2222 %d\n Ssh port should be 22: %d\n", listen_port, dst_port);

            server(sshaddr, servaddr, key_file);
        }
        exit(EXIT_SUCCESS);
    }




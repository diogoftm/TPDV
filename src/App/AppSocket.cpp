#include "AppSocket.h"

#include <openssl/conf.h>
#include <string>
#include <functional>

namespace BaseMessageLayer {

    
    int send_message(SSL* ssl, uint8_t* message, uint32_t len) {

        uint32_t packet_length = 4 + sizeof(uint8_t) * len;
        uint8_t* packet = (uint8_t*)malloc(packet_length);


        memcpy(packet + 4, message, len);
        *(uint32_t*)packet = len;

        int bytesWritten = SSL_write(ssl, packet, packet_length);

        if(bytesWritten <= 0) {
            fprintf(stderr, "Unable to write, error code := %d\n", SSL_get_error(ssl, bytesWritten));
        }

        return 0;
    }

    int receive_message(SSL* ssl, uint8_t** dst_message_buffer, int& len) {
        uint32_t mlenbuff;
        uint32_t bytes_read;
        bytes_read = SSL_read(ssl, &mlenbuff, 4);

        if(bytes_read >= 1 && bytes_read <= 3) {
            fprintf(stderr, "Expected 4 bytes\n");
            return -1;
        }

        if(bytes_read <= 0) {
            fprintf(stderr, "ssl connection error := %d\n", SSL_get_error(ssl, bytes_read));
            return -1;
            
        }

        uint32_t packet_length = mlenbuff;

        if(packet_length > 1024 * 1024) {
            fprintf(stderr, "Packet length is too big\n");
            return -1;
        }

        uint8_t* leadingBytesBuffer = (uint8_t*)malloc(sizeof(uint8_t) * packet_length);

        bytes_read = SSL_read(ssl, leadingBytesBuffer, packet_length);

        if(bytes_read >= 1 && bytes_read < packet_length) { // I think this check is unnecessary
            fprintf(stderr, "Expected %d bytes\n", packet_length);
            free(leadingBytesBuffer);
            return -1;
        }
        if(bytes_read <= 0) {
            fprintf(stderr, "ssl connection error := %d\n", SSL_get_error(ssl, bytes_read));
            free(leadingBytesBuffer);
            return -1;
        }

        *dst_message_buffer = leadingBytesBuffer;
        len = packet_length;

        return 0;
    }

}

namespace TlsServer {
    int static create_socket(int port) {


        int s;
        struct sockaddr_in addr;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            perror("Unable to create socket");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0) {
            perror("Unable to listen");
            exit(-1);
        }

        return s;
    }

    static SSL_CTX* create_context() {

        const SSL_METHOD *method;
        SSL_CTX *ctx;

        method = TLS_server_method();

        ctx = SSL_CTX_new(method);
        if (!ctx) {
            perror("Unable to create SSL context");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        return ctx;
    }

    static void configure_context(SSL_CTX* ctx, TlsServerConfig& config) {
        
        if (SSL_CTX_use_certificate_chain_file(ctx, config.rootCA) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        
        if (SSL_CTX_use_certificate_file(ctx, config.myCertificate, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, config.myPrivateKey, SSL_FILETYPE_PEM) <= 0 ) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    int run_server(int port, TlsServerConfig& config, std::function<int(SSL*)> onClientConnection) {

        int sock;
        SSL_CTX *ctx;

        signal(SIGPIPE, SIG_IGN);

        ctx = create_context();

        configure_context(ctx, config);

        sock = create_socket(port);

        printf("TLS Server is running ...\n");
        char buffer[256];
        for(int i=0;i<256;i++)
            buffer[i] = 0;
        while(1) {
            struct sockaddr_in addr;
            unsigned int len = sizeof(addr);
            SSL *ssl;
            const char reply[] = "test\n";

            int client = accept(sock, (struct sockaddr *) &addr, &len);
            if (client < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client);

            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            } else {
                if (onClientConnection(ssl) != 0) {
                    fprintf(stderr, "An error ocurred\n");
                } else {
                    fprintf(stdout, "Sucessfully handled client!\n");
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
        }
        
        close(sock);
        SSL_CTX_free(ctx);
    }

}

namespace TlsClient {

    int connect(TlsClientConfig& config, std::function<int(SSL*)> onServerConnection) {

        int s, len, result;
        struct sockaddr_in srv_addr;
        char buf[64];
        SSL_CTX *ctx;
        SSL *ssl;

        ctx = SSL_CTX_new(TLS_client_method());

        if(ctx == NULL) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_certificate_file(ctx, config.rootCA, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons(config.serverPort);
        if (inet_pton(AF_INET, config.serverIP, &srv_addr.sin_addr) != 1) {
            fprintf(stderr, "Error while parsing IP address\n");
            exit(EXIT_FAILURE);
        }


        s = socket(AF_INET, SOCK_STREAM, 0);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, s);

        errno = 0;
        result = connect(s, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

        if(result == -1) {

            fprintf(stderr, "errno := %d\n", errno);
            return -1;
        }


        if(result == 0) {
            result = SSL_connect(ssl);
            if(result == 1) {
                onServerConnection(ssl);
            } else {
                int error = SSL_get_error(ssl, result);
                fprintf(stderr, "error code: %d\n", error);
            }
        }

        close(s);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;

    }
}
#ifndef _APP_SOCKET_H_
#define _APP_SOCKET_H_

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include <functional>


namespace BaseMessageLayer {

    // Returns 0 iff success
    
    int send_message(SSL* ssl, uint8_t* message, uint32_t len);

    // Returns 0 iff success
    // dst_message should be freed later
    int receive_message(SSL* ssl, uint8_t** dst_message_buffer, int& len);

}


namespace TlsServer {

    struct TlsServerConfig {
        const char* rootCA;
        const char* myCertificate;
        const char* myPrivateKey;
    };


    static int create_socket(int port);
    static SSL_CTX* create_context();
    static void configure_context(SSL_CTX* ctx, TlsServer::TlsServerConfig& config);

    int run_server(int port, TlsServer::TlsServerConfig& config, std::function<int(SSL*)> onClientConnection);;
}

namespace TlsClient {


    struct TlsClientConfig {
        const char* rootCA;
        char* serverIP;
        int serverPort;
    };
    
    int connect(TlsClientConfig& config, std::function<int(SSL*)> onServerConnection);
}

#endif
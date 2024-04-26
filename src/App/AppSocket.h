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

namespace AppSocket {

    static int create_socket(int port);
    static SSL_CTX* create_context();
    static void configure_context(SSL_CTX* ctx);

    int run_server(int port);

    static bool serverRunning = false;
}

#endif
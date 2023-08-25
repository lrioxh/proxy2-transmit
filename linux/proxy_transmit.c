#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define BUFFER_SIZE (1024)

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <proxy_port> <server_ip> <server_port>\n", argv[0]);
        exit(1);
    }

    int proxy_port = atoi(argv[1]);
    char *server_ip = argv[2];
    int server_port = atoi(argv[3]);

    int proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in proxy_addr, server_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy_port);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) == -1) {
        perror("Binding failed");
        exit(1);
    }

    if (listen(proxy_socket, 5) == -1) {
        perror("Listening failed");
        exit(1);
    }

    printf("Proxy listening on port %d...\n", proxy_port);

    while (1) {
        int client_socket = accept(proxy_socket, NULL, NULL);
        if (client_socket == -1) {
            perror("Accepting client connection failed");
            continue;
        }

        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            perror("Server socket creation failed");
            close(client_socket);
            continue;
        }

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

        if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
            perror("Connecting to server failed");
            close(client_socket);
            close(server_socket);
            continue;
        }

        char buffer[BUFFER_SIZE];
        int bytes_received;
        while ((bytes_received = recv(client_socket, buffer, BUFFER_SIZE, 0)) > 0) {
            send(server_socket, buffer, bytes_received, 0);
            recv(server_socket, buffer, BUFFER_SIZE, 0);
            send(client_socket, buffer, bytes_received, 0);
        }

        close(client_socket);
        close(server_socket);
    }

    close(proxy_socket);
    return 0;
}
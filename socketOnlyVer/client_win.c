
#include <winsock2.h>
#include <stdio.h>
#include <Ws2tcpip.h>
//#include <arpe/inet.h>
#pragma comment(lib,"ws2_32.lib")

#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (10240)
#define PORT                    (4322)


int main() {

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    int clientSocket;
    struct sockaddr_in serverAddr;
    char* buffer;
    buffer = (char*)malloc(BUFSZ * sizeof(char));

    // 创建客户端socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);  // 与服务器相同的端口
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);  // 服务器的IP地址

    // 连接到服务器
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Connection failed");
        closesocket(clientSocket);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");
    printf("Type 'quit' to exit\n");

    while (1) {
        //char message[1024];            
        memset(buffer, '\0', BUFSZ);
        printf("Enter a message: ");
        fgets(buffer, BUFSZ, stdin);

        // 发送消息给服务器
        send(clientSocket, buffer, strlen(buffer), 0);

        // 退出条件
        if (strncmp(buffer, "quit", 4) == 0) {
            printf("Quitting...\n");
            break;
        }

        // 接收服务器的响应
        //char response[1024];
        recv(clientSocket, buffer, BUFSZ, 0);
        printf("Server response: %s\n", buffer);
    }

    closesocket(clientSocket);
    return 0;
}
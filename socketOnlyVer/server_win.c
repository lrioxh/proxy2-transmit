
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")


#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (10240)
#define PORT                    (4321)
int main() {

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    int serverSocket, clientSocket;
    int bytesRead=0;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    char* buffer;
    buffer = (char*)malloc(BUFSZ * sizeof(char));

    // 创建服务器socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);  // 选择一个合适的端口

    // 绑定socket到服务器地址
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Binding failed");
        closesocket(serverSocket);
        exit(EXIT_FAILURE);
    }

    // 监听连接请求
    if (listen(serverSocket, BACKLOG) == -1) {
        perror("Listening failed");
        closesocket(serverSocket);
        exit(EXIT_FAILURE);
    }

    printf("Server listening...\n");

    while (1) {
        // 接受客户端连接
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientSocket == -1) {
            perror("Accepting connection failed");
            continue;
        }

        printf("Client connected\n");

        // 处理通信
        while (1) {

            memset(buffer, '\0', BUFSZ);
            bytesRead = recv(clientSocket, buffer, BUFSZ, 0);
            if (bytesRead <= 0) {
                printf("Client disconnected\n");
                // closesocket(clientSocket);
                break;
            }
            // 检查是否为关闭消息
            if (strncmp(buffer, "quit", 4) == 0) {
                printf("Client sent quit message\n");
                // 这里可以进行一些清理工作，然后关闭连接
                // closesocket(clientSocket);
                break;
            }
            // 在这里处理接收到的数据，然后构造要发送回客户端的响应
            //sprintf(buffer, "%s-server", buffer);
            sprintf(buffer + strlen(buffer)-1, "-server");
            send(clientSocket, buffer, strlen(buffer), 0);
        }
        closesocket(clientSocket);
    }

    closesocket(serverSocket);    
    WSACleanup();//释放资源的操作
    free(buffer);
    return 0;
}
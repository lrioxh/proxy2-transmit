
#include <winsock2.h>
#include <stdio.h>
#include <Ws2tcpip.h>
//#include <arpe/inet.h>
#pragma comment(lib,"ws2_32.lib")

#define BUFSZ                   (2048)


int main()
{

    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET clientSocket = -1;
    //SOCKET servConn = -1;
    //SOCKADDR_IN servAddr = { 0 };
    SOCKADDR_IN clientAddr = { 0 };
    //int socklen = sizeof(SOCKADDR);
    int recvLen = 0;
    char sendBuf[BUFSZ] = { 0 };
    char recvBuf[BUFSZ] = { 0 };
    char ipBuf[16] = { 0 };
    char sIP[] = "192.168.232.128";
    //socket编程中，它定义了一个结构体SOCKADDR_IN来存计算机的一些信息，像socket的系统，
    //端口号，ip地址等信息，这里存储的是服务器端的计算机的信息
    //SOCKADDR_IN clientAddr;
    //clientAddr.sin_addr.S_un.S_addr = htonl("127.0.0.3");
    inet_pton(AF_INET,"127.0.0.1", &clientAddr.sin_addr.S_un.S_addr);
    //clientAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(4322);

    if (wsaStarted == 0) {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    //else {
    //    int serSocket = -1;
    //}

    if (clientSocket == SOCKET_ERROR)
    {
        printf("Socket() error:%d", WSAGetLastError());
        return;
    }
    else {
        printf_s("客户端套接字成功！%d\n", clientSocket);

        

        //前期定义了套接字，定义了服务器端的计算机的一些信息存储在clientsock_in中，
        //准备工作完成后，然后开始将这个套接字链接到远程的计算机
        //也就是第一次握手
        int r = connect(clientSocket, (SOCKADDR*)&clientAddr, sizeof(clientAddr));//开始连接
            //向服务器发出连接请求
        if (
            //connect(clientSocket, (struct  sockaddr*)&clientAddr, sizeof(SOCKADDR))
            r== INVALID_SOCKET
            ) {
            printf("%d", r);
            printf("Connect failed:%d", WSAGetLastError());
            return;
        }
        //else
        //{
        //    //接收数据
        //    recv(clientSocket, recvBuf, sizeof(recvBuf), 0);
        //    printf("%s\n", recvBuf);
        //}
       // printf("%d\n",r);

        while (1)
        {
            recvLen = recv(clientSocket, recvBuf, sizeof(recvBuf), 0);
            if (recvLen > 0)
                printf("%s\n", recvBuf);
            else if (recvLen == 0)
                printf("receive null");
            else
                printf("receive failed");
                //break;
            //printf("%s\n", recvBuf);
            gets(sendBuf);
            if (strcmp(sendBuf, "quit") == 0)
                break;
            send(clientSocket, sendBuf, strlen(sendBuf) + 1, 0);
        }

        send(clientSocket, "", strlen(sendBuf) + 1, 0);
        closesocket(clientSocket);
        //关闭服务
        WSACleanup();
        return 0;
    }
}


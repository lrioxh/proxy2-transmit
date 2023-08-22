
//TODO:1.函数包装？ 
// 2.return同时close
// 3.等待服务器阻塞
// 4.多线程？
//#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

//const int BUFSZ = 100;
#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (4096)


int main()
{
    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET midSrvSocket = -1;
    SOCKET midSrvConn = -1;
    SOCKET midClntSocket = -1;
    struct sockaddr_in midSrvAddr = { 0 };
    struct sockaddr_in midClntAddr = { 0 };
    struct sockaddr_in clntAddr = { 0 };
    int socklen = sizeof(struct sockaddr);
    int recvLen = 0;
    int iSend = 0;
    char transBuf[BUFSZ] = { 0 };
    char ipBuf[16] = { 0 };
    UINT sPORT = 4321;
    UINT cPORT = 4322;
    char sIP[] = "127.0.0.1";

    //as a client
    inet_pton(AF_INET, sIP, &midClntAddr.sin_addr.S_un.S_addr);
    midClntAddr.sin_family = AF_INET;
    midClntAddr.sin_port = htons(sPORT);

    //as a server
    midSrvAddr.sin_family = AF_INET;
    midSrvAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    midSrvAddr.sin_port = htons(cPORT);//绑定端口

    if (wsaStarted == 0) {
        midSrvSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    if (midSrvSocket == SOCKET_ERROR) {
        printf("mid: server socket error: %d\n", WSAGetLastError());
        return -1;
    }
    else {
        printf("mid: server socket seccess: %d\n", midSrvSocket);
    }
    //绑定
    if (bind(midSrvSocket, (struct sockaddr*)&midSrvAddr, socklen) == SOCKET_ERROR) {
        printf("mid: Failed bind:%d\n", WSAGetLastError());
        return -1;
    }
    if (listen(midSrvSocket, BACKLOG) == SOCKET_ERROR) {
        printf("mid: Listen failed:%d\n", WSAGetLastError());
        return -1;
    }

    while (1)
    {
        //c2s(midSrvConn, midClntSocket, transBuf);
        //s2c(midSrvConn, midClntSocket, transBuf);

        ////第二次握手，通过accept来接受对方的套接字的信息
        midSrvConn = accept(midSrvSocket, (struct sockaddr*)&clntAddr, &socklen);
        if (midSrvConn == SOCKET_ERROR) {
            printf("mid: Accept failed:%d\n", WSAGetLastError());
            break;
        }
        else {
            printf("mid: new client %d...\n", midSrvConn);
        }
        //from client
        recvLen = recv(midSrvConn, transBuf, sizeof(transBuf), 0);
        if (recvLen > 0) {
            printf("mid from clent: (%d)%s\n", recvLen, transBuf);
            //sprintf(sendBuf, BUFSZ, "%s", recvBuf);
        }
        else if (recvLen == 0) {
            printf("mid receive from clent null\n");
            //break;
        }
        else {
            printf("mid receive from clent failed\n");
            //break;
        }

        //as client to server
        if (wsaStarted == 0) {
            midClntSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
            //socke 返回类型SOCKETuint64 与printf接受int矛盾
        }
        if (midClntSocket == SOCKET_ERROR) {
            printf("mid: client socket error: %d\n", WSAGetLastError());
            return 1;
        }
        else {
            printf("mid: client socket seccess: %d\n", midClntSocket);
        }
        //向服务器发出连接请求
        if (
            connect(midClntSocket, (struct sockaddr*)&midClntAddr, sizeof(midClntAddr))
            == INVALID_SOCKET
            ) {
            //printf("%d", r);
            printf("mid: Connect failed: %d", WSAGetLastError());
            return -1;
        }
        iSend = send(midClntSocket, transBuf, strlen(transBuf) + 1, 0);
        if (iSend == SOCKET_ERROR) {
            printf("mid: send to server failed\n");
        }
        //waiting for server
        Sleep(500);
        //from server
        recvLen = recv(midClntSocket, transBuf, sizeof(transBuf), 0);
        if (recvLen > 0) {
            printf("mid from server: (%d)%s\n", recvLen, transBuf);
            //sprintf(sendBuf, BUFSZ, "%s", recvBuf);
        }
        else if (recvLen == 0) {
            printf("mid receive from server null\n");
            //break;
        }
        else {
            printf("mid receive from server failed\n");
            //break;
        }
        //to client
        iSend = send(midSrvConn, transBuf, strlen(transBuf) + 1, 0);
        if (iSend == SOCKET_ERROR) {
            printf("mid: send to client failed\n");
        }
        //Sleep(500);


    }
    closesocket(midSrvConn);//关闭
    closesocket(midSrvSocket);
    closesocket(midClntSocket);
    WSACleanup();//释放资源的操作
    return 0;
}

#include <stdio.h>
#include <iostream>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

//const int BUFSZ = 100;
#define BUFSZ 100
#define BACKLOG 5	//最大监听数

int main()
{
    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET midSrvSocket = -1;
    SOCKET midSrvConn = -1;
    SOCKET midClntSocket = -1;
    SOCKADDR_IN midSrvAddr = { 0 };
    SOCKADDR_IN midClntAddr = { 0 };
    SOCKADDR_IN clntAddr = { 0 };
    int socklen = sizeof(SOCKADDR);
    int recvLen = 0;
    int iSend = 0;
    //char toClntBuf[BUFSZ] = { 0 };
    //char fromClntBuf[BUFSZ] = { 0 };
    //char toSrvBuf[BUFSZ] = { 0 };
    //char fromSrvBuf[BUFSZ] = { 0 };
    char sendBuf[BUFSZ] = { 0 };
    char recvBuf[BUFSZ] = { 0 };
    char ipBuf[16] = { 0 };
    UINT sPORT = 12322;
    UINT cPORT = 12321;
    char sIP[] = "127.0.0.3";

    //as a client
    inet_pton(AF_INET, sIP, &midClntAddr.sin_addr.S_un.S_addr);
    //clientAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    midClntAddr.sin_family = AF_INET;
    midClntAddr.sin_port = htons(sPORT);

    //as a server
    midSrvAddr.sin_family = AF_INET;
    midSrvAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    midSrvAddr.sin_port = htons(cPORT);//绑定端口



    //as client
    if (wsaStarted == 0) {
        midClntSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    if (midClntSocket == SOCKET_ERROR){
        printf_s("mid: client socket error: %d\n", WSAGetLastError());
        return -1;
    }else {
        printf_s("mid: client socket seccess: %d\n", midClntSocket);
    }
    //向服务器发出连接请求
    if (
        connect(midClntSocket, (SOCKADDR*)&midClntAddr, sizeof(midClntAddr))
        == INVALID_SOCKET
        ) {
        //printf("%d", r);
        printf("mid: Connect failed: %d", WSAGetLastError());
        return -1;
    }
    recvLen = recv(midClntSocket, recvBuf, sizeof(recvBuf), 0);
    if (recvLen > 0)
        printf("mid recv: %s\n", recvBuf);
    else if (recvLen == 0)
        printf("mid: receive null");
    else
        printf("mid: receive failed");

    //as server
    if (wsaStarted == 0) {
        midSrvSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    if (midSrvSocket == SOCKET_ERROR) {
        printf_s("mid: server socket error: %d\n", WSAGetLastError());
        return -1;
    }else {
        printf_s("mid: server socket seccess: %d\n", midSrvSocket);
    }
    //绑定
    if (bind(midSrvSocket, (SOCKADDR*)&midSrvAddr, socklen) == SOCKET_ERROR) {
        printf("mid: Failed bind:%d\n", WSAGetLastError());
        return -1;
    }
    if (listen(midSrvSocket, BACKLOG) == SOCKET_ERROR) {
        printf("mid: Listen failed:%d\n", WSAGetLastError());
        return -1;
    }//其中第二个参数代表能够接收的最多的连接数
    printf_s("mid: waiting for client...\n");
    //int len = sizeof(SOCKADDR);
    ////第二次握手，通过accept来接受对方的套接字的信息
    midSrvConn = accept(midSrvSocket, (SOCKADDR*)&clntAddr, &socklen);

    if (midSrvConn == SOCKET_ERROR){
        printf("mid: Accept failed:%d", WSAGetLastError());
        return -1;
    }else {
        printf("mid: new client %d...\n", midSrvConn);
    }
    inet_ntop(AF_INET, &clntAddr.sin_addr.S_un.S_addr, ipBuf, sizeof(ipBuf));
    sprintf_s(sendBuf, BUFSZ, "welcome %s to middle server", ipBuf);//找对对应的IP并且将这行字打印到那里
    //发送信息
    iSend = send(midSrvConn, sendBuf, strlen(sendBuf) + 1, 0);
    if (iSend == SOCKET_ERROR) {
        printf("mid: send failed");
    }

    while (1)
    {

        //from client
        recvLen = recv(midSrvConn, recvBuf, sizeof(recvBuf), 0);
        if (recvLen > 0) {
            printf("mid from clent: (%d) %s\n", recvLen, recvBuf);
            sprintf_s(sendBuf, BUFSZ, "(%s mid)", recvBuf);
        }
        else if (recvLen == 0) {
            printf("mid receive null");
            break;
        }
        else {
            printf("mid receive failed");
            break;
        }
        //to server
        iSend = send(midClntSocket, sendBuf, strlen(sendBuf) + 1, 0);
        if (iSend == SOCKET_ERROR) {
            printf("mid: send failed");
        }
        //from server
        recvLen = recv(midClntSocket, recvBuf, sizeof(recvBuf), 0);
        if (recvLen > 0) {
            printf("mid from server: (%d) %s\n", recvLen, recvBuf);
            sprintf_s(sendBuf, BUFSZ, "(%s mid)", recvBuf);
        }
        else if (recvLen == 0) {
            printf("mid receive null");
            break;
        }
        else {
            printf("mid receive failed");
            break;
        }
        //to client
        iSend = send(midSrvConn, sendBuf, strlen(sendBuf) + 1, 0);
        if (iSend == SOCKET_ERROR) {
            printf("mid: send failed");
        }


    }
    closesocket(midSrvConn);//关闭
    closesocket(midSrvSocket);
    closesocket(midClntSocket);
    WSACleanup();//释放资源的操作
    return 0;
}

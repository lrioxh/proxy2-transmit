
//TODO:0.文件传输
// 1.函数包装？ 合法值验证
// 2.return同时close √
// 3.等待服务器阻塞
// 4.多线程？
// 5.每次建立新socket？√
//#include <unistd.h>
#include <stdio.h>
//#include <iostream>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")

//const int BUFSZ = 100;
#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (409600)


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
    //char transBuf[BUFSZ] = { 0 };
    char ipBuf[16] = { 0 };
    UINT sPORT = 4321;
    UINT cPORT = 4322;
    //char sIP[] = "127.0.0.1";



    //as a server
    midSrvAddr.sin_family = AF_INET;
    midSrvAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    midSrvAddr.sin_port = htons(cPORT);//绑定端口

    if (wsaStarted == 0) {
        midSrvSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    if (midSrvSocket == SOCKET_ERROR) {
        printf("server socket error: %d\n", WSAGetLastError());
        return -1;
    }
    else {
        printf("server socket seccess: %d\n", midSrvSocket);
    }
    //绑定
    if (bind(midSrvSocket, (struct sockaddr*)&midSrvAddr, socklen) == SOCKET_ERROR) {
        printf("Failed bind:%d\n", WSAGetLastError());
        return -1;
    }
    if (listen(midSrvSocket, BACKLOG) == SOCKET_ERROR) {
        printf("Listen failed:%d\n", WSAGetLastError());
        return -1;
    }

    while (1)
    {
        //c2s(midSrvConn, midClntSocket, transBuf);
        //s2c(midSrvConn, midClntSocket, transBuf);

        ////第二次握手，通过accept来接受对方的套接字的信息
        midSrvConn = accept(midSrvSocket, (struct sockaddr*)&clntAddr, &socklen);
        if (midSrvConn == SOCKET_ERROR) {
            printf("Accept failed:%d\n", WSAGetLastError());
            continue;
        }
        else {
            printf("new client %d...\n", midSrvConn);
        }



        //as a client
        //inet_pton(AF_INET, sIP, &midClntAddr.sin_addr.S_un.S_addr);
        midClntAddr.sin_addr.S_un.S_addr = clntAddr.sin_addr.S_un.S_addr;
        midClntAddr.sin_family = AF_INET;
        midClntAddr.sin_port = htons(sPORT);

        //as client to server
        if (wsaStarted == 0) {
            midClntSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
            //socke 返回类型SOCKETuint64 与printf接受int矛盾
        }
        if (midClntSocket == SOCKET_ERROR) {
            printf("client socket error: %d\n", WSAGetLastError());
            closesocket(midClntSocket);
            continue;
        }
        else {
            printf("client socket seccess: %d\n", midClntSocket);
        }
        //向服务器发出连接请求
        if (
            connect(midClntSocket, (struct sockaddr*)&midClntAddr, sizeof(midClntAddr))
            == INVALID_SOCKET
            ) {
            //printf("%d", r);
            printf("Connect failed: %d\n", WSAGetLastError());
            closesocket(midSrvConn);
            closesocket(midClntSocket);//关闭
            //closesocket(midSrvConn);
            continue;
        }
        //maybe new thread
        char transBuf[BUFSZ] = { 0 };
        //while ((recvLen = recv(midSrvConn, transBuf, BUFSZ, 0)) > 1) {
        //    printf("%d\n", recvLen);
        //    send(midClntSocket, transBuf, recvLen, 0);
        //    Sleep(10);
        //    recv(midClntSocket, transBuf, BUFSZ, 0);
        //    send(midSrvConn, transBuf, recvLen, 0);
        //}
        //from client
        //while(1){
        recvLen = recv(midSrvConn, transBuf, BUFSZ, 0);
        if (recvLen > 0) {
            printf("from clent: (%d)%s\n", recvLen, transBuf);
            //sprintf(sendBuf, BUFSZ, "%s", recvBuf);
        }
        else if (recvLen == 0) {
            printf("receive from clent null\n");
            break;
        }
        else {
            printf("receive from clent failed\n");
            break;
        }
        //to server
        iSend = send(midClntSocket, transBuf, recvLen, 0);
        if (iSend == SOCKET_ERROR) {
            printf("send to server failed\n");
            break;
        }
        //waiting for server
        Sleep(50);
        //from server
        recvLen = recv(midClntSocket, transBuf, BUFSZ, 0);
        if (recvLen > 0) {
            printf("from server: (%d)%s\n", recvLen, transBuf);
            //sprintf(sendBuf, BUFSZ, "%s", recvBuf);
        }
        else if (recvLen == 0) {
            printf("receive from server null\n");
            break;
        }
        else {
            printf("receive from server failed\n");
            break;
        }
        //to client
        iSend = send(midSrvConn, transBuf, recvLen, 0);
        if (iSend == SOCKET_ERROR) {
            printf("send to client failed\n");
            break;
        }
    }
        //Sleep(500);
        closesocket(midSrvConn);
        closesocket(midClntSocket);//关闭


    //}
    //closesocket(midSrvConn);//关闭
    closesocket(midSrvSocket);
    //closesocket(midClntSocket);
    WSACleanup();//释放资源的操作
    return 0;
}

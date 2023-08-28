
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")


#define PORT  4321		//端口号;
#define BACKLOG 5	//最大监听数
#define BUFSZ 4096

int main()
{

    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET servSocket = -1;
    SOCKET servConn = -1;
    SOCKADDR_IN servAddr = { 0 };
    SOCKADDR_IN clientAddr = { 0 };
    int socklen = sizeof(SOCKADDR);
    int recvLen = 0;
    int iSend = 0;
    char sendBuf[BUFSZ]={0};
    char recvBuf[BUFSZ]={0};
    char ipBuf[16]={0};


    if (wsaStarted == 0) {
        servSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    }
    //else {
    //    int serSocket = -1;
    //}
    
    if (servSocket == SOCKET_ERROR)
    {
        printf_s("创建socket失败！\n");
        return 0;
    }
    else {
        printf_s("成功创建套接字！%d\n", servSocket);
    }

    //需要绑定的参数，主要是本地的socket的一些信息。
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    servAddr.sin_port = htons(PORT);//绑定端口
    //addrServ.sin_addr.s_addr = inet_addr("127.0.0.1");    //将iP地址127.0.0.1也就是本机地址转换为十进制

    //int retVal = bind(servSocket, (SOCKADDR*)&servAddr, sizeof(SOCKADDR));
    if (bind(servSocket, (SOCKADDR*)&servAddr, socklen) == SOCKET_ERROR){
        printf("Failed bind:%d\n", WSAGetLastError());
        return;
    }//绑定完成
    if (listen(servSocket, BACKLOG) == SOCKET_ERROR) {
        printf("Listen failed:%d", WSAGetLastError());
        return;
    }//其中第二个参数代表能够接收的最多的连接数
    printf_s("等待客户端...\n");
    //int len = sizeof(SOCKADDR);
    ////第二次握手，通过accept来接受对方的套接字的信息
    servConn = accept(servSocket, (SOCKADDR*)&clientAddr, &socklen);
    ////如果这里不是accept而是conection的话。。就会不断的监听
    if (servConn == SOCKET_ERROR)
    {
        printf("Accept failed:%d", WSAGetLastError());
        return;
    }
    else {
        printf("监听到新的客户端 %d...\n", servConn);
    }
    inet_ntop(AF_INET, &clientAddr.sin_addr.S_un.S_addr, ipBuf, sizeof(ipBuf));
    sprintf_s(sendBuf, BUFSZ, "welcome %s to server", ipBuf);//找对对应的IP并且将这行字打印到那里
    while (1)
    {
        //发送信息
        iSend = send(servConn, sendBuf, strlen(sendBuf) + 1, 0);
        if (iSend == SOCKET_ERROR) {
            printf("send failed");
            // break;
        }
        //char receiveBuf[100];//接收
        //int RecvLen=0;
        //memset(recvBuf, 0, sizeof(recvBuf));
        recvLen = recv(servConn, recvBuf, sizeof(recvBuf), 0);

        if (recvLen > 0) {
            printf("%d %s\n", recvLen, recvBuf);
            sprintf_s(sendBuf, BUFSZ, "(%s server)", recvBuf);
        }
        else if (recvLen == 0) {
            printf("receive null");
            break;
        }
        else {
            printf("receive failed");
            break;
        }
    }
    closesocket(servConn);//关闭
    closesocket(servSocket);
    WSACleanup();//释放资源的操作
    return 0;
}

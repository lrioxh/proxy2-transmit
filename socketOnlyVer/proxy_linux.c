// TODO:
// 1.translogic out of date, only one socketconn can be established each run

#include<stdio.h>  
#include<stdlib.h>  
// #include<string.h>  
#include<errno.h>  
#include<sys/types.h>  
// #include<sys/socket.h>  
#include<sys/unistd.h>  
#include<netinet/in.h>  

#include<arpa/inet.h>
#include<netinet/ip.h>

//const int BUFSZ = 100;

#define BACKLOG                 (5)	//最大监听数
#define BUFSZ                   (100)
#define SOCKET_ERROR            (-1)

//sudo tcpdump -iany tcp port 12321

int main()
{
    // WSADATA wsaData;
    // int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    int midSrvSocket = -1;
    int midSrvConn = -1;
    int midClntSocket = -1;
    struct sockaddr_in  midSrvAddr = { 0 };
    struct sockaddr_in  midClntAddr = { 0 };
    struct sockaddr_in  clntAddr = { 0 };
    socklen_t socklen = sizeof(clntAddr);
    ssize_t recvLen = 0;
    ssize_t iSend = 0;
    //char toClntBuf[BUFSZ] = { 0 };
    //char fromClntBuf[BUFSZ] = { 0 };
    //char toSrvBuf[BUFSZ] = { 0 };
    //char fromSrvBuf[BUFSZ] = { 0 };
    char sendBuf[BUFSZ] = { 0 };
    char recvBuf[BUFSZ] = { 0 };
    char ipBuf[16] = { 0 };
    uint32_t sPORT = 12322;
    uint32_t cPORT = 12321;
    char sIP[] = "192.168.232.132";

    //as a client
    inet_pton(AF_INET, sIP, &midClntAddr.sin_addr.s_addr);
    //clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);//ip地址
    midClntAddr.sin_family = AF_INET;
    midClntAddr.sin_port = htons(sPORT);

    //as a server
    midSrvAddr.sin_family = AF_INET;
    midSrvAddr.sin_addr.s_addr = htonl(INADDR_ANY);//ip地址
    midSrvAddr.sin_port = htons(cPORT);//绑定端口



    //as client
    // if (wsaStarted == 0) {
    midClntSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    // }
    if (midClntSocket == SOCKET_ERROR){
        printf("mid: client socket error: %d\n", midClntSocket);
        return -1;
    }else {
        printf("mid: client socket seccess: %d\n", midClntSocket);
    }
    //向服务器发出连接请求
    if (
        connect(midClntSocket, (struct sockaddr*)&midClntAddr, sizeof(midClntAddr))
        == SOCKET_ERROR
        ) {
        //printf("%d", r);
        printf("mid: Connect failed: ");
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
    // if (wsaStarted == 0) {
    midSrvSocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
        //socke 返回类型SOCKETuint64 与printf接受int矛盾
    // }
    if (midSrvSocket == SOCKET_ERROR) {
        printf("mid: server socket error: %d\n",midSrvSocket);
        return -1;
    }else {
        printf("mid: server socket seccess: %d\n", midSrvSocket);
    }
    //绑定
    if (bind(midSrvSocket, (struct sockaddr*)&midSrvAddr, socklen) == SOCKET_ERROR) {
        printf("mid: Failed bind:\n");
        return -1;
    }
    if (listen(midSrvSocket, BACKLOG) == SOCKET_ERROR) {
        printf("mid: Listen failed:\n");
        return -1;
    }//其中第二个参数代表能够接收的最多的连接数
    printf("mid: waiting for client...\n");
    //int len = sizeof(SOCKADDR);
    ////第二次握手，通过accept来接受对方的套接字的信息
    midSrvConn = accept(midSrvSocket, (struct sockaddr*)&clntAddr, &socklen);

    if (midSrvConn == SOCKET_ERROR){
        printf("mid: Accept failed:%d", midSrvConn);
        return -1;
    }else {
        printf("mid: new client %d...\n", midSrvConn);
    }
    inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, ipBuf, sizeof(ipBuf));
    sprintf(sendBuf, "welcome %s to middle server", ipBuf);//找对对应的IP并且将这行字打印到那里
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
            sprintf(sendBuf, "(%s mid)", recvBuf);
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
            sprintf(sendBuf, "(%s mid)", recvBuf);
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
    close(midSrvConn);//关闭
    close(midSrvSocket);
    close(midClntSocket);
    // WSACleanup();//释放资源的操作
    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>  
#include <sys/time.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#define BACKLOG                 (5)	//最大监听数
#define BUFSIZE                 (10240)
#define PORT2SERV               (4321)
#define PORT2CLNT               (4322)
#define nonBlockMode            (1)

//sudo tcpdump -iany tcp port 4322

// int main(int argc, char *argv[]) {
int main() {

    int proxySocket = -1;
    int proxyConn2Clnt = -1;
    int proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr = { 0 };
    struct sockaddr_in proxyAddr2Serv = { 0 };
    struct sockaddr_in clntAddr = { 0 };
    int addrSize = sizeof(struct sockaddr);
    int recvByte = 0;
    int iSend = 0;
    char* transBuf;
    transBuf = (char*)malloc(BUFSIZE*sizeof(char));
    char ipBuf[16] = "192.168.137.1";
    int nonBlockFlags=0;

    unsigned long nonBlockingMode = 1;
    unsigned long blockingMode = 0; 
    struct timeval timeout;
    timeout.tv_sec = 5;  // 设置超时为5秒
    timeout.tv_usec = 0;

    //as a server
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY);//ip地址
    proxyAddr.sin_port = htons(PORT2CLNT);//绑定端口

    do{
        proxySocket = socket(AF_INET, SOCK_STREAM, 0);
        if (proxySocket < 0 ) {
            printf("%s(%d)Socket error:%d\n", __func__, __LINE__, errno);
            break;
        }   
        if (bind(proxySocket, (struct sockaddr*)&proxyAddr, addrSize) <0) {
            printf("%s(%d)Failed bind:%d\n", __func__, __LINE__, errno);
            break;
        }     
        if (listen(proxySocket, BACKLOG) <0) {
            printf("%s(%d)Listen failed:%d\n", __func__, __LINE__, errno);
            break;
        }
        printf("proxy listening...\n");
        //maybe new thread
        while (1){
            proxyConn2Clnt = accept(proxySocket, (struct sockaddr*)&clntAddr, &addrSize);
            if (proxyConn2Clnt <0) {
                printf("%s(%d)Accept failed:%d\n", __func__, __LINE__, errno);
                continue;
            }else {
                printf("\nNew Client %d...\n", proxyConn2Clnt);
            }
            setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));//超时返回-1          
            nonBlockFlags = fcntl(proxyConn2Clnt, F_GETFL, 0);

            inet_pton(AF_INET, ipBuf, &proxyAddr2Serv.sin_addr.s_addr);
            // proxyAddr2Serv.sin_addr.s_addr = clntAddr.sin_addr.s_addr;
            proxyAddr2Serv.sin_family = AF_INET;
            proxyAddr2Serv.sin_port = htons(PORT2SERV);

            proxySocket2Serv = socket(AF_INET, SOCK_STREAM, 0);
            if (proxySocket2Serv <0) {
                printf("%s(%d)Client socket error: %d\n",__func__, __LINE__, errno);
                close(proxySocket2Serv);
                continue;
            }
            setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));//超时返回-1
            if (
                connect(proxySocket2Serv, (struct sockaddr*)&proxyAddr2Serv, addrSize)
                <0
                ) {
                printf("%s(%d)Connect to server failed: %d\n",__func__, __LINE__, errno);
                close(proxySocket2Serv);//关闭
                close(proxyConn2Clnt);
                continue;
            }
            //
            while (1) {
                memset(transBuf, 0, BUFSIZE);

                //from client 阻塞
                recvByte = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                if (recvByte > 0) {
                    printf("from clent: (%d)\n", recvByte);
                    //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                }else {
                    printf("connection closed\n");
                    break;
                }
# if nonBlockMode
                fcntl(proxyConn2Clnt, F_SETFL, nonBlockFlags | O_NONBLOCK);
# endif
                while (1) {
                    //to server
                    iSend = send(proxySocket2Serv, transBuf, recvByte, 0);
                    if (iSend <0) {
                        printf("send to server failed\n");
                        break;
                    }
                    //from client
                    recvByte = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                    if (recvByte > 0) {
                        printf("from clent: (%d)\n", recvByte);
                        //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    }else {
                        printf("receive from clent finished\n");
                        break;
                    }
                }
# if nonBlockMode
                fcntl(proxyConn2Clnt, F_SETFL, nonBlockFlags & ~O_NONBLOCK);
# endif
                while (1) {
                    //from server
                    recvByte = recv(proxySocket2Serv, transBuf, BUFSIZE, 0);
                    if (recvByte > 0) {
                        printf("from server: (%d)\n", recvByte);
                        //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    }else {
                        printf("receive from server finished\n");
                        break;
                    }
                    //to client
                    iSend = send(proxyConn2Clnt, transBuf, recvByte, 0);
                    if (iSend <0) {
                        printf("send to client failed\n");
                        break;
                    }
                }
            }
            close(proxySocket2Serv);//关闭
            close(proxyConn2Clnt);



        }

    }while(0);


    if (proxyConn2Clnt > 0) {
        close(proxyConn2Clnt);
    }
    if (proxySocket > 0) {
        close(proxySocket);
    }    
    if (proxySocket2Serv > 0) {
        close(proxySocket2Serv);
    }
    free(transBuf);
    return 0;
}

//TODO:0.文件传输 √
// 1.函数包装？ 合法值验证
// 2.多线程？epoll(linux)
// 3.上传（c2s）循环阻塞在recv无法退出 链接设置非阻塞模式√超时break√
// 4.openssl
// 5.缓冲区队列?
// 6.非阻塞注册事件or阻塞-非阻收发-阻塞
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32.lib")


//const int BUFSIZE = 100;
#define BACKLOG                 (5)	//最大监听数
#define BUFSIZE                 (102400)
#define PORT2SERV               (4321)
#define PORT2CLNT               (4322)
#define nonBlockMode            (1)

int wsaTimeoutEvent(SOCKET proxySocket2Serv,DWORD time_out) {
    WSAEVENT event = WSACreateEvent();
    if (event == WSA_INVALID_EVENT) {
        perror("WSACreateEvent failed");
        return 1;
    }

    if (WSAEventSelect(proxySocket2Serv, event, FD_CONNECT) == SOCKET_ERROR) {
        perror("WSAEventSelect failed");
        WSACloseEvent(event);
        return 1;
    }
    //DWORD time_out = 10000; // 设置连接超时为10秒
    DWORD wait_result = WSAWaitForMultipleEvents(1, &event, FALSE, time_out, FALSE);
    if (wait_result == WSA_WAIT_TIMEOUT) {
        // 超时处理：连接未能在超时时间内完成
        printf("Connection timed out\n");
        return 1;
    }
    else if (wait_result == WSA_WAIT_EVENT_0) {
        // 套接字可写，连接已建立
        printf("Connected successfully\n");
        return 0;
    }
    else {
        perror("WSAWaitForMultipleEvents failed");
        return 1;
    }

    WSACloseEvent(event);
}

int main()
{

    WSADATA wsaData;
    int wsaStarted = WSAStartup(MAKEWORD(2, 2), &wsaData); //目前建议使用最新2.2版本
    SOCKET proxySocket = -1;
    SOCKET proxyConn2Clnt = -1;
    SOCKET proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr = { 0 };
    struct sockaddr_in proxyAddr2Serv = { 0 };
    struct sockaddr_in clntAddr = { 0 };
    int addrSize = sizeof(struct sockaddr);
    //int recvBytes = 0;
    //int sendBytes = 0;
    //char* transBuf;
    //transBuf = (char*)malloc(BUFSIZE*sizeof(char));
    char ipBuf[16] = "127.0.0.1";

    unsigned long nonBlockingMode = 1;
    unsigned long blockingMode = 0; 
    struct timeval timeout;
    timeout.tv_sec = 5;  // 设置超时为5秒
    timeout.tv_usec = 0;


    //as a server
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
    proxyAddr.sin_port = htons(PORT2CLNT);//绑定端口

    do {

        if (wsaStarted == 0) {
            proxySocket = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
            //socke 返回类型SOCKETuint64 与printf接受int矛盾
        }
        if (proxySocket == SOCKET_ERROR) {
            printf("Socket error: %d\n", WSAGetLastError());
            break;
        }
        else {
            printf("Socket seccess: %d\n", proxySocket);
        }
        //绑定
        if (bind(proxySocket, (struct sockaddr*)&proxyAddr, addrSize) == SOCKET_ERROR) {
            printf("Failed bind:%d\n", WSAGetLastError());
            break;
        }
        //阻塞
        if (listen(proxySocket, BACKLOG) == SOCKET_ERROR) {
            printf("Listen failed:%d\n", WSAGetLastError());
            break;
        }
        printf("proxy listening...\n");

        //maybe new thread
        while (1)
        {
            ////阻塞 第二次握手，通过accept来接受对方的套接字的信息
            proxyConn2Clnt = accept(proxySocket, (struct sockaddr*)&clntAddr, &addrSize);
            if (proxyConn2Clnt == SOCKET_ERROR) {
                printf("Accept failed:%d\n", WSAGetLastError());
                continue;
            }
            else {
                printf("New client %d...\n", proxyConn2Clnt);
            }

#if nonBlockMode
            ioctlsocket(proxyConn2Clnt, FIONBIO, &nonBlockingMode);
#endif
            setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));//recv超时返回-1
            setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));//send超时返回-1

            //as a client
            inet_pton(AF_INET, ipBuf, &proxyAddr2Serv.sin_addr.s_addr);
            //proxyAddr2Serv.sin_addr.S_un.S_addr = clntAddr.sin_addr.S_un.S_addr;
            proxyAddr2Serv.sin_family = AF_INET;
            proxyAddr2Serv.sin_port = htons(PORT2SERV);

            //as client to server
            if (wsaStarted == 0) {
                proxySocket2Serv = socket(AF_INET, SOCK_STREAM, 0);//协议族，Socket类型，创建了可识别套接字
                //socke 返回类型SOCKETuint64 与printf接受int矛盾
            }
            if (proxySocket2Serv == SOCKET_ERROR) {
                printf("client socket error: %d\n", WSAGetLastError());
                closesocket(proxySocket2Serv);
                continue;
            }
            else {
                printf("client socket seccess: %d\n", proxySocket2Serv);
            }
#if nonBlockMode
            //ioctlsocket(proxySocket2Serv, FIONBIO, &nonBlockingMode);
#endif
            setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(proxySocket2Serv, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            //向服务器发出连接请求
            int error_code = connect(proxySocket2Serv, (struct sockaddr*)&proxyAddr2Serv, addrSize);
            //if (result == -1 && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
            if (error_code !=0) {
                error_code = WSAGetLastError();
                if (error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS) {
                    //WSAEVENT event = WSACreateEvent();
                    //if (event == WSA_INVALID_EVENT) {
                    //    perror("WSACreateEvent failed");
                    //    continue;
                    //}

                    //if (WSAEventSelect(proxySocket2Serv, event, FD_CONNECT) == SOCKET_ERROR) {
                    //    perror("WSAEventSelect failed");
                    //    WSACloseEvent(event);
                    //    continue;
                    //}
                    //DWORD time_out = 10000; // 设置连接超时为10秒
                    //DWORD wait_result = WSAWaitForMultipleEvents(1, &event, FALSE, time_out, FALSE);
                    //if (wait_result == WSA_WAIT_TIMEOUT) {
                    //    // 超时处理：连接未能在超时时间内完成
                    //    printf("Connection timed out\n");
                    //    continue;
                    //}
                    //else if (wait_result == WSA_WAIT_EVENT_0) {
                    //    // 套接字可写，连接已建立
                    //    printf("Connected successfully\n");
                    //}
                    //else {
                    //    perror("WSAWaitForMultipleEvents failed");
                    //    continue;
                    //}

                    //WSACloseEvent(event);
                }else {
                    //printf("%d", r);
                    printf("Connect failed: %d\n", WSAGetLastError());
                    closesocket(proxySocket2Serv);//关闭
                    closesocket(proxyConn2Clnt);
                    continue;
                }         
            }

            int recvBytes = 0;
            int sendBytes = 0;
            char* transBuf;
            transBuf = (char*)malloc(BUFSIZE * sizeof(char));
            while (1) {
                memset(transBuf, 0, BUFSIZE);

                //from client 阻塞
                // recvBytes = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                // if (recvBytes > 0) {
                //     printf("from clent: (%d)\n", recvBytes);
                //     //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                // }
                // else {
                //     printf("connection closed\n");
                //     break;
                // }

#if nonBlockMode
                // ioctlsocket(proxyConn2Clnt, FIONBIO, &nonBlockingMode);
#endif
                while (1) {
                    // //to server
                    // sendBytes = send(proxySocket2Serv, transBuf, recvBytes, 0);
                    // if (sendBytes == SOCKET_ERROR) {
                    //     printf("send to server failed\n");
                    //     break;
                    // }
                    // //Sleep(2);
                    // //from client
                    recvBytes = recv(proxyConn2Clnt, transBuf, BUFSIZE, 0);
                    // if (recvBytes > 0) {
                    //     printf("from clent: (%d)\n", recvBytes);
                    //     //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    // }
                    // else {
                    //     printf("receive from clent finished\n");
                    //     break;
                    // }

                    if (recvBytes == -1) {
                        //if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        error_code = WSAGetLastError();
                        if (error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS){
                            // 套接字没有数据可读，继续循环
                            continue;
                        } else {
                            // 处理接收错误
                            printf("%s %d recv from clnt error=%d\n", __func__, __LINE__, errno);
                            break;
                        }
                    } else if (recvBytes == 0) {
                        // 对端关闭了连接
                        printf("recv from clnt finished\n");
                        break;
                    } else {
                        // 处理接收到的数据
                        printf("from clent: (%d)\n", recvBytes);
                        // 发送数据
                        sendBytes = send(proxySocket2Serv, transBuf, recvBytes, 0);
                        if (sendBytes == -1) {
                            //if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            error_code = WSAGetLastError();
                            if (error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS) {
                                // 套接字暂时无法发送数据，继续循环
                                continue;
                            } else {
                                // 处理发送错误
                                printf("%s %d send to serv error=%d\n", __func__, __LINE__, errno);
                                break;
                            }
                        }
                    }
                }
#if nonBlockMode
                // ioctlsocket(proxyConn2Clnt, FIONBIO, &blockingMode);
#endif
                //ioctlsocket(proxySocket2Serv, FIONBIO, &nonBlockingMode);
                while (1) {
                    // //from server
                    recvBytes = recv(proxySocket2Serv, transBuf, BUFSIZE, 0);
                    // if (recvBytes > 0) {
                    //     printf("from server: (%d)\n", recvBytes);
                    //     //sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                    // }
                    // else {
                    //     printf("receive from server finished\n");
                    //     break;
                    // }
                    // //to client
                    // sendBytes = send(proxyConn2Clnt, transBuf, recvBytes, 0);
                    // if (sendBytes == SOCKET_ERROR) {
                    //     printf("send to client failed\n");
                    //     break;
                    // }
                    if (recvBytes == -1) {
                        //if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        error_code = WSAGetLastError();
                        if (error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS) {
                            // 套接字没有数据可读，继续循环
                            continue;
                        } else {
                            // 处理接收错误
                            printf("%s %d recv from serv error=%d\n", __func__, __LINE__, errno);
                            break;
                        }
                    } else if (recvBytes == 0) {
                        // 对端关闭了连接
                        printf("recv from serv finished\n");
                        break;
                    } else {
                        // 处理接收到的数据
                        printf("from serv: (%d)\n", recvBytes);
                        // 发送数据
                        sendBytes = send(proxyConn2Clnt, transBuf, recvBytes, 0);
                        if (sendBytes == -1) {
                            //if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            error_code = WSAGetLastError();
                            if (error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS) {
                                // 套接字暂时无法发送数据，继续循环
                                continue;
                            } else {
                                // 处理发送错误
                                printf("%s %d send to clnt error=%d\n", __func__, __LINE__, errno);
                                break;
                            }
                        }
                    }
                }

                //ioctlsocket(proxySocket2Serv, FIONBIO, &blockingMode);
            }
            free(transBuf);
            closesocket(proxyConn2Clnt);
            closesocket(proxySocket2Serv);//关闭
        }

    }while (0);

    if (proxyConn2Clnt > 0) {
        closesocket(proxyConn2Clnt);
    }
    if (proxySocket > 0) {
        closesocket(proxySocket);
    }    
    if (proxySocket2Serv > 0) {
        closesocket(proxySocket2Serv);
    }

    WSACleanup();//释放资源的操作
    //free(transBuf);
    return 0;
}

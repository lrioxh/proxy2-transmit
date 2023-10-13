// TODO
// epoll
// ssl
// test nonblock wait event
// select?
// clean code

// sudo tcpdump -iany tcp port 4322

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_EVENTS (10) // epoll
#define BACKLOG (5)     // 最大监听数
#define BUFSIZE (102400)
#define PORT2SERV (4321)
#define PORT2CLNT (4322)
#define nonBlockMode (1)

// int main(int argc, char *argv[]) {
int main()
{

    int proxySocket = -1;
    struct sockaddr_in proxyAddr = {0};
    socklen_t addrSize = sizeof(struct sockaddr);
    int proxyConn2Clnt = -1;
    struct sockaddr_in clntAddr = {0};
    int proxySocket2Serv = -1;
    struct sockaddr_in proxyAddr2Serv = {0};

    int recvBytes = 0;
    int sendBytes = 0;
    char *transBuf;
    transBuf = (char *)malloc(BUFSIZE * sizeof(char));
    char ipBuf[16] = "192.168.137.1";

    int nonBlockFlags = 0;
    struct timeval timeout;
    timeout.tv_sec = 5; // 设置超时为5秒
    timeout.tv_usec = 0;

    int epoll_fd = -1;
    int epoll_ready = 0;
    struct epoll_event event, events[MAX_EVENTS];

    // as a server
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_addr.s_addr = htonl(INADDR_ANY); // ip地址
    proxyAddr.sin_port = htons(PORT2CLNT);         // 绑定端口

    do
    {
        proxySocket = socket(AF_INET, SOCK_STREAM, 0);
        if (proxySocket < 0)
        {
            printf("%s(%d)Socket error:%d\n", __func__, __LINE__, errno);
            break;
        }
        if (bind(proxySocket, (struct sockaddr *)&proxyAddr, addrSize) < 0)
        {
            printf("%s(%d)Failed bind:%d\n", __func__, __LINE__, errno);
            break;
        }
        if (listen(proxySocket, BACKLOG) < 0)
        {
            printf("%s(%d)Listen failed:%d\n", __func__, __LINE__, errno);
            break;
        }
        // 创建epoll实例
        epoll_fd = epoll_create1(0);
        if (epoll_fd == -1)
        {
            printf("%s(%d)Epoll creation failed:%d\n", __func__, __LINE__, errno);
            break;
        }

        // 注册服务器socket到epoll
        event.events = EPOLLIN;
        event.data.fd = proxySocket;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxySocket, &event) == -1)
        {
            printf("%s(%d)Epoll control error:%d\n", __func__, __LINE__, errno);
            break;
        }
        printf("proxy listening...\n");
        // maybe new thread
        while (1)
        {
            epoll_ready = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

            if (epoll_ready < 0)
            {
                printf("%s(%d)Epoll wait error:%d\n", __func__, __LINE__, errno);
                continue;
            }
            for (int i = 0; i < epoll_ready; i++)
            {
                if (events[i].data.fd == proxySocket)
                {
                    // 有新的连接请求
                    proxyConn2Clnt = -1;
                    // struct sockaddr_in clntAddr = { 0 };
                    proxyConn2Clnt = accept(proxySocket, (struct sockaddr *)&clntAddr, &addrSize);
                    if (proxyConn2Clnt < 0)
                    {
                        printf("%s(%d)Accept failed:%d\n", __func__, __LINE__, errno);
                        continue;
                    }
                    else
                    {
                        printf("\nNew Client %d...\n", proxyConn2Clnt);
                    }
                    setsockopt(proxyConn2Clnt, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1
                    // nonBlockFlags = fcntl(proxyConn2Clnt, F_GETFL, 0);

                    // 将客户端socket注册到epoll
                    event.events = EPOLLIN;
                    event.data.fd = proxyConn2Clnt;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxyConn2Clnt, &event) == -1)
                    {
                        printf("%s(%d)Epoll control error:%d\n", __func__, __LINE__, errno);
                        close(proxyConn2Clnt);
                        continue;
                    }
                }
                else
                {
                    proxySocket2Serv = -1;
                    // struct sockaddr_in proxyAddr2Serv = { 0 };
                    inet_pton(AF_INET, ipBuf, &proxyAddr2Serv.sin_addr.s_addr);
                    // proxyAddr2Serv.sin_addr.s_addr = clntAddr.sin_addr.s_addr;
                    proxyAddr2Serv.sin_family = AF_INET;
                    proxyAddr2Serv.sin_port = htons(PORT2SERV);

                    nonBlockFlags = fcntl(events[i].data.fd, F_GETFL, 0);
                    do
                    {
                        proxySocket2Serv = socket(AF_INET, SOCK_STREAM, 0);
                        if (proxySocket2Serv < 0)
                        {
                            printf("%s(%d)Client socket error: %d\n", __func__, __LINE__, errno);
                            continue;
                        }
                        setsockopt(proxySocket2Serv, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)); // 超时返回-1
                        if (
                            connect(proxySocket2Serv, (struct sockaddr *)&proxyAddr2Serv, addrSize) < 0)
                        {
                            printf("%s(%d)Connect to server failed: %d\n", __func__, __LINE__, errno);
                            close(proxySocket2Serv);
                            continue;
                        }
                        // 有数据可读
                        // int recvBytes=0,sendBytes=0;
                        // char* transBuf;
                        // transBuf = (char*)malloc(BUFSIZE*sizeof(char));
                        while (1)
                        {
                            memset(transBuf, '\0', sizeof(transBuf));

                            recvBytes = recv(events[i].data.fd, transBuf, BUFSIZE, 0);
                            if (recvBytes > 0)
                            {
                                printf("from clent: (%d)\n", recvBytes);
                                // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                sendBytes = send(proxySocket2Serv, transBuf, recvBytes,0);
                                if (sendBytes < 0)
                                {
                                    printf("send to server failed\n");
                                    break;
                                }
                            }
                            else if (recvBytes == 0)
                            {
                                // 客户端断开连接或出错，从epoll中移除
                                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                                // close(events[i].data.fd);
                                printf("Client disconnected:%d %d\n", recvBytes, errno);
                                break;
                            }
                            else
                            {
                                printf("Client connect error:%d %d\n", recvBytes, errno);
                                break;
                            }
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlags | O_NONBLOCK);
#endif
                            while (1)
                            {
                                recvBytes = recv(events[i].data.fd, transBuf, BUFSIZE,0);
                                if (recvBytes > 0)
                                {
                                    printf("from clent: (%d)\n", recvBytes);
                                    // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                    // send here
                                    sendBytes = send(proxySocket2Serv, transBuf, recvBytes,0);
                                    if (sendBytes < 0)
                                    {
                                        printf("send to server failed\n");
                                        break;
                                    }
                                }
                                else if (recvBytes == 0)
                                {
                                    printf("receive from clent finished:%d %d\n", recvBytes, errno);
                                    break;
                                }
                                else
                                {
                                    // int errn = SSL_get_error(events[i].data.fd, recvBytes);
                                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                                    {
                                        // continue;
                                        // should bind wait event
                                        printf("receive from clent finished:%d %d\n", recvBytes, errno);
                                        break;
                                    }
                                    else
                                    {
                                        // 处理接收错误
                                        printf("%s %d recv from clnt error=%d\n", __func__, __LINE__, errno);
                                        break;
                                    }
                                }
                            }
#if nonBlockMode
                            fcntl(events[i].data.fd, F_SETFL, nonBlockFlags & ~O_NONBLOCK);

#endif
                            while (1)
                            {
                                // from server
                                //  recvBytes = recv(proxySocket2Serv, transBuf, BUFSIZE, 0);
                                recvBytes = recv(proxySocket2Serv, transBuf, BUFSIZE,0);
                                if (recvBytes > 0)
                                {
                                    printf("from server: (%d)\n", recvBytes);
                                    // sprintf(sendBuf, BUFSIZE, "%s", recvBuf);
                                    sendBytes = send(events[i].data.fd, transBuf, recvBytes,0);
                                    if (sendBytes < 0)
                                    {
                                        printf("send to client failed\n");
                                        break;
                                    }
                                }
                                else if (recvBytes == 0)
                                {
                                    printf("receive from serv finished:%d %d\n", recvBytes, errno);
                                    break;
                                }
                                else
                                {
                                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        // 处理接收错误
                                        printf("%s %d recv from serv error=%d\n", __func__, __LINE__, errno);
                                        break;
                                    }
                                }
                            }
                            // if (recvBytes == 0)
                            // {
                            //     printf("Client disconnected:%d %d\n", recvBytes, errno);
                            //     break;
                            // }
                        }
                    } while (0);
                    // free(transBuf);
                    // close(proxySocket2Serv);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    close(events[i].data.fd);
                }
            }
        }

    } while (0);

    if (proxyConn2Clnt > 0) {
        close(proxyConn2Clnt);
    }
    if (proxySocket > 0)
    {
        close(proxySocket);
    }
    if (proxySocket2Serv > 0) {
        close(proxySocket2Serv);
    }
    free(transBuf);
    return 0;
}
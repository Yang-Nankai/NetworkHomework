#ifndef SERVER_H
#define SERVER_H
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#define MYPORT 8888   /*定义服务器端口*/
#define BACKLOG 5  /*定义最大连接数*/
#define IP "127.0.0.1"  /*定义自己的IP地址*/

//加密发送
void ServerEncrptSend(char* key, char* content);
//开启聊天
int StartServerChat();
//接收消息线程
void* ServerRecvThread(void* args);
//服务器主函数
int server();

#endif

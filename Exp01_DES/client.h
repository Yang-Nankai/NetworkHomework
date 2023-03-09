#ifndef CLIENT_H
#define CLIENT_H
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

#define MYPORT 8888   /*定义服务器端口*/
#define IP "127.0.0.1"  /*定义自己的IP地址*/

//加密发送数据
void ClientEncrptSend(char* key, char* content);
//接收线程
void* ClientRecvThread(void* args);
//开启聊天
void StartClientChat();
//客户端程序
int client();

#endif

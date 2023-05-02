#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <tchar.h>
#include <fstream>
#include <string>
#include <winsock2.h>
#include <cstdlib>
#include <ctime>
#include "RSA.h"
#include "MD5.h"
#include "AES.h"
#include "protocol.h"

#pragma comment(lib, "ws2_32.lib")

#define MYPORT 8888   /*定义服务器端口*/
#define BACKLOG 5  /*定义最大连接数*/
#define IP "127.0.0.1"  /*定义自己的IP地址*/
#define RSA_LEN 1024 /*定义RSA长度为1024位*/
#define DES_LEN 128 /*定义DES长度位128位*/
#define RAND_LEN 128 /*定义三个随机的长度*/

using namespace std;
using ycdfwzy::BigInt;
using ycdfwzy::RSA;
BigInt n, e, d;
string session_key;
vector<BigInt> encryption;
SOCKET m_Client;
bool isRecv = false;  //用来表明现在是否应该接收消息，主要用于接收消息线程

//开启服务
int StartChat();
//专门用来处理接收消息的线程函数
DWORD WINAPI RecvThread(LPVOID args);
//用来进行刚开始的会话密钥分配
bool agreementBegin();
//用DES进行加密发送
void EncrptSend(string content, string key);

int main() {

	//初始化WSA
	WORD ver = MAKEWORD(2, 2);
	WSADATA dat;
	if (WSAStartup(ver, &dat) != 0)return -1;

	/*server socket相关*/
	SOCKET sev_fd;  //监听sev_fd，新的连接cli_fd
	struct sockaddr_in sev_addr;  //服务器IP信息

	//启动chat server
	printf("[ INFO ] Welecome to Yang's Crypto Big Homework!\n");
	printf("[ INFO ] Author: Yang-Nankai\n");
	printf("[ INFO ] Time: 2022/12/20\n");
	printf("[ INFO ] CryptoServer ready to run, please hold on...\n");
	sev_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sev_fd == INVALID_SOCKET) {
		perror("[ ERR ] Socket error!");  //分配失败退出
		exit(1);
	}

	memset(&sev_addr, 0, sizeof(sev_addr)); //先用0填充
	sev_addr.sin_family = AF_INET;  //地址类型
	sev_addr.sin_port = htons(MYPORT); //端口号
	sev_addr.sin_addr.s_addr = inet_addr(IP);    //本地IP 127.0.0.1

	//进行绑定
	if (bind(sev_fd, (struct sockaddr*)&sev_addr, sizeof(struct sockaddr)) == SOCKET_ERROR) {
		perror("[ ERRO ] Bind error!");
		exit(1);
	}

	//进行监听
	if (listen(sev_fd, BACKLOG) == SOCKET_ERROR) {
		perror("[ ERRO ] Listen error!");
		exit(1);
	}

	printf("[ INFO ] CryptoServer is running，waiting for client...\n");
	printf("[ INFO ] My IP Address: %s \n", inet_ntoa(sev_addr.sin_addr));

	//循环接收连接
	DWORD ThreadID;
	struct sockaddr_in cli_addr;
	int sin_size = sizeof(struct sockaddr_in);
	while (1) {
		//进行接受
		if ((m_Client = accept(sev_fd, (struct sockaddr*)&cli_addr, &sin_size)) == INVALID_SOCKET) {
			perror("[ ERRO ] Accept error!\n");
			continue;
		}
		//接下来进行程序会话密钥的交接
		if (!agreementBegin()) {
			printf("[ ERRO ] Protocol is something wrong!\n");
			closesocket(m_Client);
			continue;
		}
		printf("[ INFO ] Client is now running，it's IP address: %s\n", inet_ntoa(cli_addr.sin_addr));
		CreateThread(NULL, 0, RecvThread, &m_Client, 0, &ThreadID);
		if (StartChat() == 0) {
			break;
		}
		closesocket(m_Client);

	}

	//关闭socket
	closesocket(sev_fd);
	WSACleanup();
	return 0;
}


int StartChat() {
	string message;  //输入消息
	/*
	* quit; 退出程序
	*/
	cout << "[ INFO ] Send Message Indirectly(Less Than 1020 Bytes)!\n";
	while (TRUE) {
		getline(cin, message, '\n');
		if (message == "exit") {
			cout << "[ Exit ] Server Not Quit, Continue To Waiting For New Client!\n";
			isRecv = false;
			return 1;
		}
		if (message == "quit") {
			cout << "[Bye - Bye] See You Again!\n";
			isRecv = false;
			closesocket(m_Client);
			return 0;
		}
		else {
			cout << "[INFO] your message : " << message << endl;
			EncrptSend(message, session_key);
		}
	}
}


//接收消息线程
DWORD WINAPI RecvThread(LPVOID args) {
	SOCKET client = *(SOCKET*)args;
	if (client == INVALID_SOCKET)
	{
		printf("[ INFO ] Accept error !");
		closesocket(client);
	}
	//接收消息类型判断是哪种类型 1是直接聊天、2是文件名、3是文件内容
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	while (isRecv) {
		int ret = recv(client, message, MAXDATALEN, 0);
		if (ret > 0) {
			//解析协议包
			chatbody = (chatBody*)message;
			string result = decrypt_cbc(chatbody->content, chatbody->m_length, session_key);
			cout << "[ RECV ] Recvfrom Server Message => " << result << endl;
		}
	}
	closesocket(client);
	return NULL;
}

void EncrptSend(string content, string key) {
	chatBody* sendBody = new chatBody;
	char ciphertext[MESSAGELEN];
	int len = encrypt_cbc(content, ciphertext, key);
	sendBody->m_length = len;
	strcpy(sendBody->content, ciphertext);
	//通过send将得到的密文发送出去
	send(m_Client, (char*)sendBody, MAXDATALEN, NULL);
}

bool agreementBegin() {
	int ret = 0;
	chatBody* sendBody = new chatBody;
	chatBody* recvBody = new chatBody;
	BigInt r1, r2, r3;  //用来保存三个随机数
	char message[MAXDATALEN + 1];

	//首先接收客户端第一个随机数
	char rand1[RAND_LEN / 4 + 1];
	ret = recv(m_Client, rand1, RAND_LEN / 4, 0);
	if (ret > 0) {
		rand1[RAND_LEN / 4] = '\0';
		r1 = BigInt(rand1, 16);
		//cout << "[ RAND1 ] RecvFrom Rand1 is => " << r1 <<endl;
	}
	//然后服务端生成自己的RSA公玥和私玥
	cout << "[ INFO ] Waiting to generate RSA...." << endl;
	ULONGLONG start = GetTickCount64();
	RSA::rsa(n, e, d, RSA_LEN);
	ULONGLONG finish = GetTickCount64();
	//cout <<"[ RSA_1024 ] " << finish - start << " ms to generate RSA numbers" << endl;
	//cout << "[ RSA_N ] N: 0x" << n << endl;
	//cout << "[ RSA_E ] Public key: 0x" << e << endl;
	//cout << "[ RSA_D ] Private key: 0x" << d << endl;

	//然后服务端生成第二个随机数，并将第二个随机数以及公钥(e,N)发送给服务端
	srand((int)time(0));
	string rand2 = md5(to_string(rand() % 1000));
	r2 = BigInt(rand2, 16);
	//cout << "[ RAND2 ] Your Rand2 is => "<< r2 << endl;
	send(m_Client, rand2.c_str(), rand2.length(), NULL);
	
	//cout << "[ RSA_E ] Your Public Key is => " << e << endl;
	memset(sendBody, 0, sizeof(chatBody));
	sendBody->m_length = e.toString(16).length();
	strcpy(sendBody->content, e.toString(16).c_str());
	send(m_Client,(char*)sendBody, MAXDATALEN, NULL);
	//cout << "sendbody" << sendBody->m_length << sendBody->content << endl;
	//cout << "[ RSA_N ] Your Public N is => " << n << endl;
	memset(sendBody, 0, sizeof(chatBody));
	sendBody->m_length = n.toString(16).length();
	strcpy(sendBody->content, n.toString(16).c_str());
	send(m_Client, (char*)sendBody, MAXDATALEN, NULL);

	//服务器接收预主密钥
	string rand3;
	BigInt c;
	ret = recv(m_Client, message, MAXDATALEN, 0);
	if (ret > 0) {
		recvBody = (chatBody*)message;
		int length = recvBody->m_length;
		string rsa_m = recvBody->content;
		rsa_m = rsa_m.substr(0, length);
		c = BigInt(rsa_m, 16);
		r3 = RSA::decrypt(c, d, n);
		rand3 = r3.toString(16);
	}
	//cout << "[ RAND3 ] RecvFrom Rand3 is => " << rand3 << endl;
	if (rand1 == "" || rand2 == "" || rand3 == "") {
		cout << "[ ERRO ] Haven't recvieve one of rands!" << endl;
		return false;
	}

	//做完以上工作后后，就可以生成会话密钥了
	//会话密钥的计算为md5( r1 + r2 + r3)
	session_key = md5((r1 + r2 + r3).toString(16));
	//cout << "[ SESSION_KEY ] Session Key is => " << session_key << endl;
	//发送OK表明已经生成会话密钥了，这里已经可以使用AES进行加密了
	string ok = "ok";
	EncrptSend(ok, session_key);

	//进行完以上后就进入了正式加密通信的环节了
	isRecv = true;
	return true;
}
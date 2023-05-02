#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
//#define _CRT_SECURE_NO_WARNINGS
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
#define IP "127.0.0.1"  /*定义自己的IP地址*/
#define RSA_LEN 1024 /*定义RSA长度为1024位*/
#define DES_LEN 128 /*定义DES长度位128位*/
#define RAND_LEN 128 /*定义三个随机的长度*/

using namespace std;
using ycdfwzy::BigInt;
using ycdfwzy::RSA;
BigInt n, e;
string session_key;
vector<BigInt> encryption;
SOCKET m_Server;
bool isRecv = false;  //用来表明现在是否应该接收消息，主要用于接收消息线程

//接收消息线程
DWORD WINAPI RecvThread(LPVOID args);
//开启服务
void StartChat();
//用来进行刚开始的会话密钥分配
bool agreementBegin();
//用DES进行加密发送
void EncrptSend(string content, string key);

int main()
{
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return 0;
	}
	m_Server = -1;
	int ret = -1;
	m_Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Server == -1) {
		perror("[ ERRO ] Socket error!\n");
		closesocket(m_Server);
		exit(1);
	}

	if (m_Server == INVALID_SOCKET)
	{
		perror("[ ERRO ]Invalid socket!\n");
		return 0;
	}

	struct sockaddr_in serAddr;
	memset(&serAddr, 0, sizeof(serAddr)); //先用0填充
	serAddr.sin_family = AF_INET; //设置tcp协议族
	serAddr.sin_port = htons(MYPORT); //设置端口号
	serAddr.sin_addr.s_addr = inet_addr(IP); //设置ip地址
	if (connect(m_Server, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
	{  //连接失败
		perror("[ ERRO ] Connect error!\n");
		closesocket(m_Server);
		WSACleanup();
		return 0;
	}
	if (!agreementBegin()) {
		printf("[ ERRO ] Protocol is something wrong!\n");
		closesocket(m_Server);
		WSACleanup();
		return 0;
	}
	printf("[ INFO ] 成功连接服务器...\n");
	DWORD ThreadID;

	//调用线程接受从服务端返回的消息
	CreateThread(NULL, 0, RecvThread, &m_Server, 0, &ThreadID);
	StartChat();
	closesocket(m_Server);

	WSACleanup();
	return 0;

}

void EncrptSend(string content, string key) {
	chatBody* sendBody = new chatBody;
	char ciphertext[MESSAGELEN];
	int len = encrypt_cbc(content, ciphertext, key);
	sendBody->m_length = len;
	strcpy(sendBody->content, ciphertext);
	//通过send将得到的密文发送出去
	send(m_Server, (char*)sendBody, MAXDATALEN, NULL);
}

bool agreementBegin() {
	int ret = 0;
	char message[MAXDATALEN + 1];
	chatBody* recvBody = new chatBody;
	chatBody* sendBody = new chatBody;
	BigInt r1, r2, r3;  //用来保存三个随机数

	//首先客户端发送第一个随机数(由随机数+MD5生成的128位)
	srand((int)time(0));
	string rand1 = md5(to_string(rand() % 1000));
	r1 = BigInt(rand1, 16);
	//cout << "[ RAND1 ] Your Rand1 is => " << r1 << endl;
	send(m_Server, rand1.c_str(), rand1.length(), NULL);

	//然后客户端接收第二个随机数
	char rand2[RAND_LEN / 4 + 1];
	ret = recv(m_Server, rand2, RAND_LEN / 4, 0);
	if (ret > 0) {
		rand2[RAND_LEN / 4] = '\0';
		r2 = BigInt(rand2, 16);
		//cout << "[ RAND2 ] RecvFrom Rand2 is => " << r2 << endl;
	}

	//然后客户端接收服务端发送来的RSA公钥(e,N)
	ret = recv(m_Server, message, MAXDATALEN, 0);
	if (ret > 0) {
		recvBody = (chatBody*)message;
		int length = recvBody->m_length;
		string rsa_e = recvBody->content;
		rsa_e = rsa_e.substr(0, length);
		e = BigInt(rsa_e, 16);
		//cout << "[ RSA_E ] RecvFrom RSA Public E is => 0x" << rsa_e << endl;
	}

	ret = recv(m_Server, message, MAXDATALEN, 0);
	if (ret > 0) {
		recvBody = (chatBody*)message;
		int length = recvBody->m_length;
		string rsa_n = recvBody->content;
		rsa_n = rsa_n.substr(0, length);
		n = BigInt(rsa_n, 16);
		//cout << "[ RSA_E ] RecvFrom RSA Public N is => 0x" << rsa_n << endl;
	}

	//然后客户端生成第三个随机数也就是预主密钥，通过RSA_E进行加密
	srand((int)time(0));
	string rand3 = md5(to_string(rand() % 1000));
	r3 = BigInt(rand3, 16);
	//cout << "[ RAND3 ] Your Rand3 is => " << rand3 << endl;
	//进行RSA加密quit
	BigInt c = RSA::encrypt(r3, e, n);
	//cout << "[ INFO ] Encrypt(RSA) Rand3 is => " << endl;
	sendBody->m_length = c.toString(16).length();
	strcpy(sendBody->content, c.toString(16).c_str());
	send(m_Server, (char*)sendBody, MAXDATALEN, NULL);
	Sleep(10);
	if (rand1 == "" || rand2 == "" || rand3 == "") {
		//cout << "[ ERRO ] Haven't recvieve one of rands!" << endl;
		return false;
	}
	//等待服务器发送OK表明服务器已经接收到rand3并生成会话密钥了

	//做完以上工作后后，就可以生成会话密钥了
	//会话密钥的计算为md5( r1 + r2 + r3)
	session_key = md5((r1 + r2 + r3).toString(16));
	//cout << "[ SESSION_KEY ] Session Key is => " << session_key << endl;
	//接收服务器OK
	ret = recv(m_Server, message, MAXDATALEN, 0);
	if (ret > 0) {
		recvBody = (chatBody*)message;
		string result = decrypt_cbc(recvBody->content, recvBody->m_length, session_key);
		cout << "ok => "<<  result << endl;
		if (result != "ok")
			return false;
	}

	//进行完以上后就进入了正式加密通信的环节了
	isRecv = true;
	return true;
}

DWORD WINAPI RecvThread(LPVOID args) {
	SOCKET server = *(SOCKET*)args;
	if (server == INVALID_SOCKET)
	{
		printf("[ INFO ] Accept error !");
		closesocket(server);
	}

	//接收消息类型判断是哪种类型 1是直接聊天、2是文件名、3是文件内容
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	while (isRecv) {
		int ret = recv(server, message, MAXDATALEN, 0);
		if (ret > 0) {
			//解析协议包
			chatbody = (chatBody*)message;
			string result = decrypt_cbc(chatbody->content, chatbody->m_length, session_key);
			cout << "[ RECV ] Recvfrom Server Message => " << result << endl;
		}
	}
	closesocket(server);
	return NULL;
}

void StartChat() {
	string message;  //输入消息
	/*
	* quit; 退出程序
	*/
	cout << "[ INFO ] Send Message Indirectly(Less Than 1020 Bytes)!\n";
	while (TRUE) {
		getline(cin, message, '\n');
		if (message == "quit") {
			cout << "[ Bye-Bye ] See You Again!\n";
			isRecv = false;
			return;
		}
		else {
			cout << "[INFO] your message : " << message << endl;
			EncrptSend(message, session_key);
			//send(m_Server, sendData, sendbody->m_length + HEADERLEN, NULL);
		}
	}
}
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

#define MYPORT 8888   /*����������˿�*/
#define BACKLOG 5  /*�������������*/
#define IP "127.0.0.1"  /*�����Լ���IP��ַ*/
#define RSA_LEN 1024 /*����RSA����Ϊ1024λ*/
#define DES_LEN 128 /*����DES����λ128λ*/
#define RAND_LEN 128 /*������������ĳ���*/

using namespace std;
using ycdfwzy::BigInt;
using ycdfwzy::RSA;
BigInt n, e, d;
string session_key;
vector<BigInt> encryption;
SOCKET m_Client;
bool isRecv = false;  //�������������Ƿ�Ӧ�ý�����Ϣ����Ҫ���ڽ�����Ϣ�߳�

//��������
int StartChat();
//ר���������������Ϣ���̺߳���
DWORD WINAPI RecvThread(LPVOID args);
//�������иտ�ʼ�ĻỰ��Կ����
bool agreementBegin();
//��DES���м��ܷ���
void EncrptSend(string content, string key);

int main() {

	//��ʼ��WSA
	WORD ver = MAKEWORD(2, 2);
	WSADATA dat;
	if (WSAStartup(ver, &dat) != 0)return -1;

	/*server socket���*/
	SOCKET sev_fd;  //����sev_fd���µ�����cli_fd
	struct sockaddr_in sev_addr;  //������IP��Ϣ

	//����chat server
	printf("[ INFO ] Welecome to Yang's Crypto Big Homework!\n");
	printf("[ INFO ] Author: Yang-Nankai\n");
	printf("[ INFO ] Time: 2022/12/20\n");
	printf("[ INFO ] CryptoServer ready to run, please hold on...\n");
	sev_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sev_fd == INVALID_SOCKET) {
		perror("[ ERR ] Socket error!");  //����ʧ���˳�
		exit(1);
	}

	memset(&sev_addr, 0, sizeof(sev_addr)); //����0���
	sev_addr.sin_family = AF_INET;  //��ַ����
	sev_addr.sin_port = htons(MYPORT); //�˿ں�
	sev_addr.sin_addr.s_addr = inet_addr(IP);    //����IP 127.0.0.1

	//���а�
	if (bind(sev_fd, (struct sockaddr*)&sev_addr, sizeof(struct sockaddr)) == SOCKET_ERROR) {
		perror("[ ERRO ] Bind error!");
		exit(1);
	}

	//���м���
	if (listen(sev_fd, BACKLOG) == SOCKET_ERROR) {
		perror("[ ERRO ] Listen error!");
		exit(1);
	}

	printf("[ INFO ] CryptoServer is running��waiting for client...\n");
	printf("[ INFO ] My IP Address: %s \n", inet_ntoa(sev_addr.sin_addr));

	//ѭ����������
	DWORD ThreadID;
	struct sockaddr_in cli_addr;
	int sin_size = sizeof(struct sockaddr_in);
	while (1) {
		//���н���
		if ((m_Client = accept(sev_fd, (struct sockaddr*)&cli_addr, &sin_size)) == INVALID_SOCKET) {
			perror("[ ERRO ] Accept error!\n");
			continue;
		}
		//���������г���Ự��Կ�Ľ���
		if (!agreementBegin()) {
			printf("[ ERRO ] Protocol is something wrong!\n");
			closesocket(m_Client);
			continue;
		}
		printf("[ INFO ] Client is now running��it's IP address: %s\n", inet_ntoa(cli_addr.sin_addr));
		CreateThread(NULL, 0, RecvThread, &m_Client, 0, &ThreadID);
		if (StartChat() == 0) {
			break;
		}
		closesocket(m_Client);

	}

	//�ر�socket
	closesocket(sev_fd);
	WSACleanup();
	return 0;
}


int StartChat() {
	string message;  //������Ϣ
	/*
	* quit; �˳�����
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


//������Ϣ�߳�
DWORD WINAPI RecvThread(LPVOID args) {
	SOCKET client = *(SOCKET*)args;
	if (client == INVALID_SOCKET)
	{
		printf("[ INFO ] Accept error !");
		closesocket(client);
	}
	//������Ϣ�����ж����������� 1��ֱ�����졢2���ļ�����3���ļ�����
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	while (isRecv) {
		int ret = recv(client, message, MAXDATALEN, 0);
		if (ret > 0) {
			//����Э���
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
	//ͨ��send���õ������ķ��ͳ�ȥ
	send(m_Client, (char*)sendBody, MAXDATALEN, NULL);
}

bool agreementBegin() {
	int ret = 0;
	chatBody* sendBody = new chatBody;
	chatBody* recvBody = new chatBody;
	BigInt r1, r2, r3;  //�����������������
	char message[MAXDATALEN + 1];

	//���Ƚ��տͻ��˵�һ�������
	char rand1[RAND_LEN / 4 + 1];
	ret = recv(m_Client, rand1, RAND_LEN / 4, 0);
	if (ret > 0) {
		rand1[RAND_LEN / 4] = '\0';
		r1 = BigInt(rand1, 16);
		//cout << "[ RAND1 ] RecvFrom Rand1 is => " << r1 <<endl;
	}
	//Ȼ�����������Լ���RSA���h��˽�h
	cout << "[ INFO ] Waiting to generate RSA...." << endl;
	ULONGLONG start = GetTickCount64();
	RSA::rsa(n, e, d, RSA_LEN);
	ULONGLONG finish = GetTickCount64();
	//cout <<"[ RSA_1024 ] " << finish - start << " ms to generate RSA numbers" << endl;
	//cout << "[ RSA_N ] N: 0x" << n << endl;
	//cout << "[ RSA_E ] Public key: 0x" << e << endl;
	//cout << "[ RSA_D ] Private key: 0x" << d << endl;

	//Ȼ���������ɵڶ���������������ڶ���������Լ���Կ(e,N)���͸������
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

	//����������Ԥ����Կ
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

	//�������Ϲ�����󣬾Ϳ������ɻỰ��Կ��
	//�Ự��Կ�ļ���Ϊmd5( r1 + r2 + r3)
	session_key = md5((r1 + r2 + r3).toString(16));
	//cout << "[ SESSION_KEY ] Session Key is => " << session_key << endl;
	//����OK�����Ѿ����ɻỰ��Կ�ˣ������Ѿ�����ʹ��AES���м�����
	string ok = "ok";
	EncrptSend(ok, session_key);

	//���������Ϻ�ͽ�������ʽ����ͨ�ŵĻ�����
	isRecv = true;
	return true;
}
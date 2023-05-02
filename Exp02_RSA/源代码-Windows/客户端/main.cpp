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

#define MYPORT 8888   /*����������˿�*/
#define IP "127.0.0.1"  /*�����Լ���IP��ַ*/
#define RSA_LEN 1024 /*����RSA����Ϊ1024λ*/
#define DES_LEN 128 /*����DES����λ128λ*/
#define RAND_LEN 128 /*������������ĳ���*/

using namespace std;
using ycdfwzy::BigInt;
using ycdfwzy::RSA;
BigInt n, e;
string session_key;
vector<BigInt> encryption;
SOCKET m_Server;
bool isRecv = false;  //�������������Ƿ�Ӧ�ý�����Ϣ����Ҫ���ڽ�����Ϣ�߳�

//������Ϣ�߳�
DWORD WINAPI RecvThread(LPVOID args);
//��������
void StartChat();
//�������иտ�ʼ�ĻỰ��Կ����
bool agreementBegin();
//��DES���м��ܷ���
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
	memset(&serAddr, 0, sizeof(serAddr)); //����0���
	serAddr.sin_family = AF_INET; //����tcpЭ����
	serAddr.sin_port = htons(MYPORT); //���ö˿ں�
	serAddr.sin_addr.s_addr = inet_addr(IP); //����ip��ַ
	if (connect(m_Server, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
	{  //����ʧ��
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
	printf("[ INFO ] �ɹ����ӷ�����...\n");
	DWORD ThreadID;

	//�����߳̽��ܴӷ���˷��ص���Ϣ
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
	//ͨ��send���õ������ķ��ͳ�ȥ
	send(m_Server, (char*)sendBody, MAXDATALEN, NULL);
}

bool agreementBegin() {
	int ret = 0;
	char message[MAXDATALEN + 1];
	chatBody* recvBody = new chatBody;
	chatBody* sendBody = new chatBody;
	BigInt r1, r2, r3;  //�����������������

	//���ȿͻ��˷��͵�һ�������(�������+MD5���ɵ�128λ)
	srand((int)time(0));
	string rand1 = md5(to_string(rand() % 1000));
	r1 = BigInt(rand1, 16);
	//cout << "[ RAND1 ] Your Rand1 is => " << r1 << endl;
	send(m_Server, rand1.c_str(), rand1.length(), NULL);

	//Ȼ��ͻ��˽��յڶ��������
	char rand2[RAND_LEN / 4 + 1];
	ret = recv(m_Server, rand2, RAND_LEN / 4, 0);
	if (ret > 0) {
		rand2[RAND_LEN / 4] = '\0';
		r2 = BigInt(rand2, 16);
		//cout << "[ RAND2 ] RecvFrom Rand2 is => " << r2 << endl;
	}

	//Ȼ��ͻ��˽��շ���˷�������RSA��Կ(e,N)
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

	//Ȼ��ͻ������ɵ����������Ҳ����Ԥ����Կ��ͨ��RSA_E���м���
	srand((int)time(0));
	string rand3 = md5(to_string(rand() % 1000));
	r3 = BigInt(rand3, 16);
	//cout << "[ RAND3 ] Your Rand3 is => " << rand3 << endl;
	//����RSA����quit
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
	//�ȴ�����������OK�����������Ѿ����յ�rand3�����ɻỰ��Կ��

	//�������Ϲ�����󣬾Ϳ������ɻỰ��Կ��
	//�Ự��Կ�ļ���Ϊmd5( r1 + r2 + r3)
	session_key = md5((r1 + r2 + r3).toString(16));
	//cout << "[ SESSION_KEY ] Session Key is => " << session_key << endl;
	//���շ�����OK
	ret = recv(m_Server, message, MAXDATALEN, 0);
	if (ret > 0) {
		recvBody = (chatBody*)message;
		string result = decrypt_cbc(recvBody->content, recvBody->m_length, session_key);
		cout << "ok => "<<  result << endl;
		if (result != "ok")
			return false;
	}

	//���������Ϻ�ͽ�������ʽ����ͨ�ŵĻ�����
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

	//������Ϣ�����ж����������� 1��ֱ�����졢2���ļ�����3���ļ�����
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	while (isRecv) {
		int ret = recv(server, message, MAXDATALEN, 0);
		if (ret > 0) {
			//����Э���
			chatbody = (chatBody*)message;
			string result = decrypt_cbc(chatbody->content, chatbody->m_length, session_key);
			cout << "[ RECV ] Recvfrom Server Message => " << result << endl;
		}
	}
	closesocket(server);
	return NULL;
}

void StartChat() {
	string message;  //������Ϣ
	/*
	* quit; �˳�����
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
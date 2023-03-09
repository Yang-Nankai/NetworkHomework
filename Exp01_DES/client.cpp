#include "client.h"
#include "DES.h"
#include "protocol.h"
using namespace std;

char client_session_key[9] = "12345678"; //设置session_key，用于进行会话的加密与解密
int m_Server;
bool isClientRecv = false;  //用来表明现在是否应该接收消息，主要用于接收消息线程

void ClientEncrptSend(char* key, char* content) {
	chatBody* sendBody = new chatBody;
	char ciphertext[MESSAGELEN];
	strcpy(ciphertext, DESEncrypt_CBC(key, content));
	sendBody->m_length = strlen(ciphertext);
	strcpy(sendBody->content, ciphertext);
	//通过send将得到的密文发送出去
	send(m_Server, (char*)sendBody, MAXDATALEN, NULL);
}

void* ClientRecvThread(void* args) {
	int server = *(int*)args;
	if (server == -1)
	{
		printf("[ INFO ] Accept error !");
		close(server);
	}
	//接收消息类型判断是哪种类型 1是直接聊天、2是文件名、3是文件内容
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	char result[MAXDATALEN];
	while (isClientRecv) {
		int ret = recv(server, message, MAXDATALEN, 0);
		if (ret > 0) {
			//解析协议包
			chatbody = (chatBody*)message;
			strcpy(result, DESDecrypt_CBC(client_session_key, chatbody->content));
			cout << "[ RECV ] Recvfrom Server Message => " << result << endl;
		}
	}
	close(server);
	pthread_exit(NULL);
}

void StartClientChat() {
	char message[MESSAGELEN];  //输入消息
	/*
	* quit; 退出程序
	*/
	cout << "[ INFO ] Send Message Indirectly(Less Than 1020 Bytes)!\n";
	while (true) {
		cin.ignore();
		cin.getline(message, MESSAGELEN / 2, ';');
		if (!strcmp(message, "quit")) {
			cout << "[ Bye-Bye ] See You Again!\n";
			isClientRecv = false;
			return;
		}
		else {
			cout << "[INFO] your message : " << message << endl;
			ClientEncrptSend(client_session_key, message);
		}
	}
}


int client()
{
	m_Server = -1;
	int ret = -1;
	m_Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Server == -1) {
		perror("[ ERRO ] Socket error!\n");
		close(m_Server);
		exit(1);
	}

	struct sockaddr_in serAddr;
	memset(&serAddr, 0, sizeof(serAddr)); //先用0填充
	serAddr.sin_family = AF_INET; //设置tcp协议族
	serAddr.sin_port = htons(MYPORT); //设置端口号
	serAddr.sin_addr.s_addr = inet_addr(IP); //设置ip地址
	if (connect(m_Server, (sockaddr*)&serAddr, sizeof(serAddr)) == -1)
	{  //连接失败
		perror("[ ERRO ] Connect error!\n");
		close(m_Server);
		return 0;
	}
	printf("[ INFO ] 成功连接服务器...\n");
	isClientRecv = true;
	pthread_t thread_id;
	//调用线程接受从服务端返回的消息
	int threadRet = pthread_create(&thread_id, NULL, ClientRecvThread, &m_Server);
	StartClientChat();
	close(m_Server);

	return 0;

}



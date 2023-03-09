#include "server.h"
#include "DES.h"
#include "protocol.h"
using namespace std;

char server_session_key[9] = "12345678"; //设置session_key，用于进行会话的加密与解密
int m_Client;
bool isServerRecv = false;  //用来表明现在是否应该接收消息，主要用于接收消息线程

void ServerEncrptSend(char* key, char* content) {
	chatBody* sendBody = new chatBody;
	char ciphertext[MESSAGELEN];
	strcpy(ciphertext, DESEncrypt_CBC(key, content));
	sendBody->m_length = strlen(ciphertext);
	strcpy(sendBody->content, ciphertext);
	//通过send将得到的密文发送出去
	send(m_Client, (char*)sendBody, MAXDATALEN, NULL);
}

int StartServerChat() {
	char message[MESSAGELEN];  //输入消息
	/*
	* quit; 退出程序
	*/
	cout << "[ INFO ] Send Message Indirectly(Less Than 1020 Bytes)!\n";
	while (true) {
		cin.ignore();
		cin.getline(message, MESSAGELEN / 2, ';');
		if (!strcmp(message, "exit")) {
			cout << "[ Exit ] Server Not Quit, Continue To Waiting For New Client!\n";
			isServerRecv = false;
			return 1;
		}
		if (!strcmp(message, "quit")) {
			cout << "[Bye - Bye] See You Again!\n";
			isServerRecv = false;
			close(m_Client);
			return 0;
		}
		else {
			cout << "[INFO] your message : " << message << endl;
			ServerEncrptSend(server_session_key, message);
		}
	}
}

//接收消息线程
void* ServerRecvThread(void* args) {
	int client = *(int*)args;
	if (client == -1)
	{
		printf("[ INFO ] Accept error !");
		close(client);
	}
	//接收消息类型判断是哪种类型 1是直接聊天、2是文件名、3是文件内容
	chatBody* chatbody = (chatBody*)malloc(sizeof(chatBody));
	char message[MAXDATALEN];
	char result[MAXDATALEN];
	while (isServerRecv) {
		int ret = recv(client, message, MAXDATALEN, 0);
		if (ret > 0) {
			//解析协议包
			chatbody = (chatBody*)message;
			strcpy(result, DESDecrypt_CBC(server_session_key, chatbody->content));
			cout << "[ RECV ] Recvfrom Server Message => " << result << endl;
		}
	}
	close(client);
	return NULL;
}

int server() {

	/*server socket相关*/
	int sev_fd;  //监听sev_fd，新的连接cli_fd
	struct sockaddr_in sev_addr;  //服务器IP信息

	//启动chat server
	printf("[ INFO ] Welecome to Yang's Crypto Big Homework!\n");
	printf("[ INFO ] Author: Yang-Nankai\n");
	printf("[ INFO ] Time: 2022/12/20\n");
	printf("[ INFO ] CryptoServer ready to run, please hold on...\n");
	sev_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sev_fd == -1) {
		perror("[ ERR ] Socket error!");  //分配失败退出
		exit(1);
	}

	memset(&sev_addr, 0, sizeof(sev_addr)); //先用0填充
	sev_addr.sin_family = AF_INET;  //地址类型
	sev_addr.sin_port = htons(MYPORT); //端口号
	sev_addr.sin_addr.s_addr = inet_addr(IP);    //本地IP 127.0.0.1

	//进行绑定
	if (bind(sev_fd, (struct sockaddr*)&sev_addr, sizeof(struct sockaddr)) == -1) {
		perror("[ ERRO ] Bind error!");
		exit(1);
	}

	//进行监听
	if (listen(sev_fd, BACKLOG) == -1) {
		perror("[ ERRO ] Listen error!");
		exit(1);
	}

	printf("[ INFO ] CryptoServer is running，waiting for client...\n");
	printf("[ INFO ] My IP Address: %s \n", inet_ntoa(sev_addr.sin_addr));

	//循环接收连接
	struct sockaddr_in cli_addr;
	int sin_size = sizeof(struct sockaddr_in);
	isServerRecv = true;
	while (1) {
		//进行接受
		if ((m_Client = accept(sev_fd, (struct sockaddr*)&cli_addr, (socklen_t*)&sin_size)) == -1) {
			perror("[ ERRO ] Accept error!\n");
			continue;
		}
		printf("[ INFO ] Client is now running，it's IP address: %s\n", inet_ntoa(cli_addr.sin_addr));
		pthread_t thread_id;
		//调用线程接受从client返回的消息
		int ret = pthread_create(&thread_id, NULL, ServerRecvThread, &m_Client);
		if (StartServerChat() == 0) {
			break;
		}
		close(m_Client);
	}

	//关闭socket
	close(sev_fd);
	return 0;
}


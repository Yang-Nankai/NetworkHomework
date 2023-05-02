#pragma once

#define MAXDATALEN 1024  //最大消息长度
#define HEADERLEN 4   //HEADER的长度
#define MESSAGELEN 1020 //内容最大长度

/*
用结构体来定义协议
*/
struct chatBody {
	int m_length;  //消息的长度
	char content[MESSAGELEN]; //接受的消息内容
};
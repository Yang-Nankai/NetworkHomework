#pragma once

#define MAXDATALEN 1024  //�����Ϣ����
#define HEADERLEN 4   //HEADER�ĳ���
#define MESSAGELEN 1020 //������󳤶�

/*
�ýṹ��������Э��
*/
struct chatBody {
	int m_length;  //��Ϣ�ĳ���
	char content[MESSAGELEN]; //���ܵ���Ϣ����
};
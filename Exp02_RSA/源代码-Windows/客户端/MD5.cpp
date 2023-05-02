#include"MD5.h"
#include <fstream>
#include <sstream>

//����תʮ�������ַ��� ע��С����
string int2hex(unsigned int Integer)
{
	const string strHex = "0123456789abcdef";
	unsigned x;

	string temp;
	string hexString = "";

	for (int i = 0; i < 4; i++)
	{
		temp = "";
		x = (Integer >> (i * 8)) & 0xff;

		for (int j = 0; j < 2; j++)
		{
			temp.insert(0, 1, strHex[x % 16]);
			x /= 16;
		}
		hexString += temp;
	}
	return hexString;
}

//MD5������
string md5(string message)
{
	//����A��B��C��D�ĸ����ӱ�����С����洢
	unsigned int A = 0x67452301;
	unsigned int B = 0xefcdab89;
	unsigned int C = 0x98badcfe;
	unsigned int D = 0x10325476;

	//��¼�ַ����ĳ���(�ֽ� 8λ)
	int len = message.length();
	//��¼��Ҫ����ķ����� ��512λ��64���ֽ�Ϊһ��
	int num = ((len + 8) / 64) + 1;
	u_int* messageByte = new u_int[num * 16];
	memset(messageByte, 0, sizeof(u_int) * num * 16);

	//����ַ��� 
	for (int i = 0; i < len; i++) {
		// һ��unsigned int��Ӧ4���ֽڣ�����4���ַ���Ϣ
		messageByte[i / 4] |= message[i] << ((i % 4) * 8);
	}
	// ����1000...000
	messageByte[len >> 2] |= 0x80 << ((len % 4) * 8);
	// ���ԭ�ĳ���
	messageByte[num * 16 - 2] = (len << 3);

	unsigned int a, b, c, d;

	for (int i = 0; i < num; i++)
	{
		a = A;
		b = B;
		c = C;
		d = D;
		unsigned int g;
		int k;

		//����4��
		for (int j = 0; j < 64; j++)
		{
			if (j < 16)
			{
				g = F(b, c, d);
				k = j;
			}
			else if (j >= 16 && j < 32)
			{
				g = G(b, c, d);
				k = (1 + 5 * j) % 16;
			}
			else if (j >= 32 && j < 48)
			{
				g = H(b, c, d);
				k = (5 + 3 * j) % 16;
			}
			else if (j >= 48 && j < 64)
			{
				g = I(b, c, d);
				k = (7 * j) % 16;
			}

			unsigned temp_d = d;
			d = c;
			c = b;
			b = b + shift(a + g + messageByte[i * 16 + k] + T[j], s[j]);
			a = temp_d;
		}
		A = a + A;
		B = b + B;
		C = c + C;
		D = d + D;
	}
	return int2hex(A) + int2hex(B) + int2hex(C) + int2hex(D);

}

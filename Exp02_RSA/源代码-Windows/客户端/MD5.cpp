#include"MD5.h"
#include <fstream>
#include <sstream>

//整数转十六进制字符串 注意小端序
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

//MD5处理函数
string md5(string message)
{
	//定义A、B、C、D四个链接变量，小端序存储
	unsigned int A = 0x67452301;
	unsigned int B = 0xefcdab89;
	unsigned int C = 0x98badcfe;
	unsigned int D = 0x10325476;

	//记录字符串的长度(字节 8位)
	int len = message.length();
	//记录需要处理的分组数 以512位，64个字节为一组
	int num = ((len + 8) / 64) + 1;
	u_int* messageByte = new u_int[num * 16];
	memset(messageByte, 0, sizeof(u_int) * num * 16);

	//填充字符串 
	for (int i = 0; i < len; i++) {
		// 一个unsigned int对应4个字节，保存4个字符信息
		messageByte[i / 4] |= message[i] << ((i % 4) * 8);
	}
	// 补充1000...000
	messageByte[len >> 2] |= 0x80 << ((len % 4) * 8);
	// 填充原文长度
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

		//经过4轮
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

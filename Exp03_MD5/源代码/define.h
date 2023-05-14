#ifndef DEFINE_DEFINE_H
#define DEFINE_DEFINE_H

#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <fstream>
#include <sstream>
using namespace std;

//基本逻辑函数 使用 宏定义
#define F(b,c,d) (( b & c ) | (( ~b ) & ( d )))
#define G(b,c,d) (( b & d ) | ( c & ( ~d )))
#define H(b,c,d) ( b ^ c ^ d )
#define I(b,c,d) ( c ^ ( b | ( ~d )))

//x循环左移n位 使用 宏定义
#define shift(x,n) (( x << n ) | ( x >> ( 32 - n )))

typedef unsigned int u_int;

//压缩函数每轮每步中A分块循环左移的位数
const unsigned s[64] =
{
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

//常数表T
const unsigned T[64] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};


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

#endif // DEFINE_DEFINE_H
#include<iostream>
#include<string.h>
#include <string>      // std::string
#include <sstream>     // std::stringstream
#include"DES.h"
using namespace std;


//全局变量声明区
char plaintext[200];  //存放原始明文
char inputKey[9]; //存放字符型的八位密钥
char target[8]; //将明文转为8个字符一个分组
int text[64];  //用来存放一个分组转为二进制后的数据
int text_ip[64];  //存在第一次初始换位的结果
int text_out[26][64]; //存放初始化向量和所有经过DES分组的二进制
int L0[32], R0[32]; //将64位分成左右各32位进行迭代
int Li[32], Ri[32];
int RE0[48]; //存放右半部分经过E表扩展换位后的48位数据
int RK[48];  //存放E与K异或运算后的结果
int key[64]; //存放密钥的二进制形式
int keyPC1[56]; //存放密钥key经过PC1换位表后变成的56位二进制
int keyA[28], keyB[28]; //存放keyPC1的左右两边
int keyAB[56]; //将keyA和keyB合并为56位
int K[16][48];  //存放每轮的子密钥
int text_end[64];  //存放经过32为换位后的结果
char init[9] = { "nku2020!" }; //CBC模式，设置初始化向量为"nku2020!"
int CBC[64];
int result[25][64];  //存放最后的得到的结果
int r[8], c[8]; //存放经过S盒的横、列
int RKS[8];    //存放经过查找8个S表后得到的8个十进制结果
int SP[32];     //将RKS表中的十进制数化成二进制
int RKSP[32];  //存放SP经过P盒换位后的结果
int H[400];
char ciphertext[400];  //存放密文
int C[1600];
int M[25][8];


//DES加密函数
char* DESEncrypt_CBC(char* inputKey, char* plaintext) {

	memset(ciphertext, 0, sizeof(ciphertext));

	int i = 0, n = 0, k = 0, l = 0, m = 0, j = 0, t = 0;

	//将密钥转化成64位二进制数放到一维数组key中
	for (i = 0; i < 8; i++) //将密钥转化成64位二进制数放到一维数组key中
	{
		int a[8] = { 0,0,0,0,0,0,0,0 };
		m = inputKey[i];
		for (j = 0; m != 0; j++)
		{
			a[j] = m % 2;
			m = m / 2;
		}
		for (j = 0; j < 8; j++)
			key[(i * 8) + j] = a[7 - j];
	}

	//通过PC1换位表变成56位密钥放在keyPC1中
	for (i = 0; i < 56; i++) {
		keyPC1[i] = key[PC1_Table[i] - 1];
	}

	//分成A和B两部分，各28位
	for (i = 0; i < 28; i++) //分成A和B两部分，各28位
	{
		keyA[i] = keyPC1[i];
		keyB[i] = keyPC1[i + 28];
	}

	for (t = 0; t < 16; t++)
	{
		if (LOOP_Table[t] == 1) //按照循环移位表将Ai和Bi分别左移move[t]位
		{
			n = keyA[0];
			for (i = 0; i < 27; i++)
				keyA[i] = keyA[i + 1];
			keyA[27] = n;
			n = keyB[0];
			for (i = 0; i < 27; i++)
				keyB[i] = keyB[i + 1];
			keyB[27] = n;
		}
		else
		{
			n = keyA[0];
			m = keyA[1];
			for (i = 0; i < 26; i++)
				keyA[i] = keyA[i + 2];
			keyA[26] = n;
			keyA[27] = m;
			n = keyB[0];
			m = keyB[1];
			for (i = 0; i < 26; i++)
				keyB[i] = keyB[i + 2];
			keyB[26] = n;
			keyB[27] = m;
		}

		for (i = 0; i < 28; i++) //将A和B合并成56位
		{
			keyAB[i] = keyA[i];
			keyAB[i + 28] = keyB[i];
		}

		for (i = 0; i < 48; i++) //通过PC2换位表变成48位密钥
			K[t][i] = keyAB[PC2_Table[i] - 1];
	}

	for (i = 0; i < 8; i++) //将初始化向量转化成二进制数储存到数组text_out的第一行中
	{
		int a[8] = { 0,0,0,0,0,0,0,0 };
		m = init[i];
		for (j = 0; m != 0; j++)
		{
			a[j] = m % 2;
			m = m / 2;
		}
		for (j = 0; j < 8; j++)
			text_out[0][(i * 8) + j] = a[7 - j];
	}


	if (plaintext[0] == '\0') {
		return NULL;
	}

	/*
	* CBC模式：密码分组链接模式，一次对一个明文分组加密，每次加密使用同一密钥，加密算法的输入是当前明文分组和前一次密文分组的异或
	* 目的是为了让重复的明文产生不同的密文分组结果
	*/

	i = 0;
	n = 0;
	while (plaintext[i] != '\0')
	{
		n++;
		i++;
	}
	k = n % 8;
	n = (n - 1) / 8 + 1;

	for (l = 0; l < n; l++)
	{
		if (l == (n - 1) && k != 0)
		{
			for (i = 0; i < k; i++) //将每个分组的8个字符放到数组target中，不够的用空格补充
				target[i] = plaintext[i + (8 * l)];
			for (i = k; i < 8; i++)
				target[i] = ' ';
		}
		else
			for (i = 0; i < 8; i++)
				target[i] = plaintext[i + (8 * l)];

		for (i = 0; i < 8; i++) //将得到的明文转化成二进制数储存到数组text中
		{
			int a[8] = { 0,0,0,0,0,0,0,0 };
			m = target[i];
			for (j = 0; m != 0; j++)
			{
				a[j] = m % 2;
				m = m / 2;
			}
			for (j = 0; j < 8; j++)
				text[(i * 8) + j] = a[7 - j];
		}

		//CBC模式下前一个分组的密文异或当前分组
		for (i = 0; i < 64; i++)
			text[i] = text_out[l][i] ^ text[i];

		//对每个text进行DES加密
		for (i = 0; i < 64; i++)  //进行初始换位
			text_ip[i] = text[IP_Table[i] - 1];

		//分为左右两部分，各32位
		for (i = 0; i < 32; i++)
		{
			L0[i] = text_ip[i];
			R0[i] = text_ip[i + 32];
		}

		//十六次迭代
		for (t = 0; t < 16; t++)
		{
			for (i = 0; i < 48; i++) //将右半部分通过扩展换位表E从32位扩展到48位
			{
				RE0[i] = R0[E_Table[i] - 1];
			}

			//RE与K异或运算
			for (i = 0; i < 48; i++)
			{
				RK[i] = RE0[i] ^ K[t][i];
			}

			//将R和K异或运算的结果通过S位移表
			for (i = 0; i < 8; i++)
			{
				r[i] = RK[(i * 6) + 0] * 2 + RK[(i * 6) + 5];
				c[i] = RK[(i * 6) + 1] * 8 + RK[(i * 6) + 2] * 4 + RK[(i * 6) + 3] * 2 + RK[(i * 6) + 4];
			}

			for (i = 0; i < 8; i++)
			{
				RKS[i] = S_Box[i * 4 + r[i]][c[i]];
			}

			//把结果转为32位二进制存储在数组SP中
			for (i = 0; i < 8; i++)
			{
				int b[4] = { 0, 0, 0, 0 };
				m = RKS[i];
				for (j = 3; m != 0; j--) {
					b[j] = m % 2;
					m = m / 2;
				}
				for (j = 0; j < 4; j++)
				{
					SP[j + (i * 4)] = b[j];
				}
			}

			//将二进制结果再经过一个P盒换位
			for (i = 0; i < 32; i++)
			{
				RKSP[i] = SP[P_Table[i] - 1];
			}
			//与前一次的左部异或运算，得到本次迭代的右部
			for (i = 0; i < 32; i++)
			{
				Ri[i] = L0[i] ^ RKSP[i];
			}

			//得到左右部分的结果
			for (i = 0; i < 32; i++)
			{
				L0[i] = R0[i];
				R0[i] = Ri[i];
			}
		}
		//一个左右32位交换
		for (i = 0; i < 32; i++)
			Li[i] = R0[i];
		for (i = 0; i < 32; i++)
			R0[i] = L0[i];
		for (i = 0; i < 32; i++)
			L0[i] = Li[i];

		//初始换位的逆过程

		for (i = 0; i < 32; i++) //把左右两部分合起来存到text_end中
			text_end[i] = L0[i];
		for (i = 32; i < 64; i++)
			text_end[i] = R0[i - 32];

		for (i = 0; i < 64; i++) //进行初始换位的逆过程
			text_out[l + 1][IP_Table[i] - 1] = text_end[i];

		for (i = 0; i < 64; i++)
			result[l][i] = text_out[l + 1][i];
	}
	for (j = 0; j < n; j++) //把result中的二进制密文转成十进制存到数组H中
		for (i = 0; i < 16; i++)
			H[i + (j * 16)] = result[j][0 + (i * 4)] * 8 + result[j][1 + (i * 4)] * 4 + result[j][2 + (i * 4)] * 2 + result[j][3 + (i * 4)];

	for (i = 0; i < n * 16; i++)
	{
		if (H[i] < 10)
			ciphertext[i] = H[i] + 48;
		else if (H[i] == 10)
			ciphertext[i] = 'A';
		else if (H[i] == 11)
			ciphertext[i] = 'B';
		else if (H[i] == 12)
			ciphertext[i] = 'C';
		else if (H[i] == 13)
			ciphertext[i] = 'D';
		else if (H[i] == 14)
			ciphertext[i] = 'E';
		else if (H[i] == 15)
			ciphertext[i] = 'F';
	}
	for (i = l * 16; i < 400; i++)
		ciphertext[i] = '\0';//注意数组越界

	return ciphertext;
}


char* DESDecrypt_CBC(char* inputKey, char* ciphertext) {

	//清空避免影响输出
	memset(plaintext, 0, sizeof(plaintext));

	int i = 0, n = 0, k = 0, l = 0, m = 0, j = 0, t = 0;

	//将密钥转化成64位二进制数放到一维数组key中
	for (i = 0; i < 8; i++) //将密钥转化成64位二进制数放到一维数组key中
	{
		int a[8] = { 0,0,0,0,0,0,0,0 };
		m = inputKey[i];
		for (j = 0; m != 0; j++)
		{
			a[j] = m % 2;
			m = m / 2;
		}
		for (j = 0; j < 8; j++)
			key[(i * 8) + j] = a[7 - j];
	}

	//通过PC1换位表变成56位密钥放在keyPC1中
	for (i = 0; i < 56; i++) {
		keyPC1[i] = key[PC1_Table[i] - 1];
	}

	//分成A和B两部分，各28位
	for (i = 0; i < 28; i++) //分成A和B两部分，各28位
	{
		keyA[i] = keyPC1[i];
		keyB[i] = keyPC1[i + 28];
	}

	for (t = 0; t < 16; t++)
	{
		if (LOOP_Table[t] == 1) //按照循环移位表将Ai和Bi分别左移move[t]位
		{
			n = keyA[0];
			for (i = 0; i < 27; i++)
				keyA[i] = keyA[i + 1];
			keyA[27] = n;
			n = keyB[0];
			for (i = 0; i < 27; i++)
				keyB[i] = keyB[i + 1];
			keyB[27] = n;
		}
		else
		{
			n = keyA[0];
			m = keyA[1];
			for (i = 0; i < 26; i++)
				keyA[i] = keyA[i + 2];
			keyA[26] = n;
			keyA[27] = m;
			n = keyB[0];
			m = keyB[1];
			for (i = 0; i < 26; i++)
				keyB[i] = keyB[i + 2];
			keyB[26] = n;
			keyB[27] = m;
		}

		for (i = 0; i < 28; i++) //将A和B合并成56位
		{
			keyAB[i] = keyA[i];
			keyAB[i + 28] = keyB[i];
		}

		for (i = 0; i < 48; i++) //通过PC2换位表变成48位密钥
			K[t][i] = keyAB[PC2_Table[i] - 1];
	}

	for (i = 0; i < 8; i++) //将初始化向量转化成二进制数储存到数组text_out的第一行中
	{
		int a[8] = { 0,0,0,0,0,0,0,0 };
		m = init[i];
		for (j = 0; m != 0; j++)
		{
			a[j] = m % 2;
			m = m / 2;
		}
		for (j = 0; j < 8; j++)
			text_out[0][(i * 8) + j] = a[7 - j];
	}

	for (i = 0; i < 400; i++)
		H[i] = '\0';

	//将十六进制密文转化成十进制存放在数组H中
	for (i = 0; ciphertext[i] != '\0'; i++)
	{
		if (ciphertext[i] >= '0' && ciphertext[i] <= '9')
			H[i] = ciphertext[i] - '0';
		else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'F')
			H[i] = ciphertext[i] - 'A' + 10;
		else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'f')
			H[i] = ciphertext[i] - 'a' + 10;
		else
		{
			return NULL;
		}
	}

	n = i; //密文中共有n个字符
	if (n % 16 != 0)
	{
		return NULL;
	}
	for (i = 0; i < n; i++) //将十进制密文转化成二进制存放在数组C中
	{
		int he[4] = { 0,0,0,0 };
		for (j = 3; H[i] != 0; j--)
		{
			he[j] = H[i] % 2;
			H[i] = H[i] / 2;
		}
		for (j = 0; j < 4; j++)
			C[j + (i * 4)] = he[j];
	}

	k = n / 16;
	for (l = 0; l < k; l++)
	{
		for (i = 0; i < 64; i++) //将每个分组对应的64位二进制密文放到text_out中
			text_out[l + 1][i] = C[i + (l * 64)];

		//对每个text进行DES解密
		for (i = 0; i < 64; i++) //进行初始换位
			text_ip[i] = text_out[l + 1][IP_Table[i] - 1];


		for (i = 0; i < 32; i++) //分成左右两部分，各32位
		{
			L0[i] = text_ip[i];
			R0[i] = text_ip[i + 32];
		}


		//十六次迭代

		for (t = 0; t < 16; t++)
		{
			for (i = 0; i < 48; i++) //将右半部分通过扩展换位表E从32位扩展成48位
				RE0[i] = R0[E_Table[i] - 1];

			for (i = 0; i < 48; i++) //RE与K异或运算
				RK[i] = RE0[i] ^ K[15 - t][i];

			for (i = 0; i < 8; i++) //将R和K异或运算的结果通过S位移表
			{
				r[i] = RK[(i * 6) + 0] * 2 + RK[(i * 6) + 5];
				c[i] = RK[(i * 6) + 1] * 8 + RK[(i * 6) + 2] * 4 + RK[(i * 6) + 3] * 2 + RK[(i * 6) + 4];
			}

			for (i = 0; i < 8; i++) {
				RKS[i] = S_Box[i * 4 + r[i]][c[i]];
			}

			for (i = 0; i < 8; i++) //把结果转成32位二进制储存在数组SP中
			{
				int b[4] = { 0,0,0,0 };
				m = RKS[i];
				for (j = 3; m != 0; j--)
				{
					b[j] = m % 2;
					m = m / 2;
				}
				for (j = 0; j < 4; j++)
					SP[j + (i * 4)] = b[j];
			}

			for (i = 0; i < 32; i++) //将二进制结果再经过一个P盒换位
				RKSP[i] = SP[P_Table[i] - 1];

			for (i = 0; i < 32; i++) //与前一次的左部异或运算，得到本次迭代的右部
				Ri[i] = L0[i] ^ RKSP[i];

			for (i = 0; i < 32; i++)
			{
				L0[i] = R0[i];
				R0[i] = Ri[i];
			}
		}

		//一个左右32位交换

		for (i = 0; i < 32; i++)
			Li[i] = R0[i];
		for (i = 0; i < 32; i++)
			R0[i] = L0[i];
		for (i = 0; i < 32; i++)
			L0[i] = Li[i];

		//初始换位的逆过程

		for (i = 0; i < 32; i++) //把左右两部分合起来存到text_end中
			text_end[i] = L0[i];
		for (i = 32; i < 64; i++)
			text_end[i] = R0[i - 32];

		for (i = 0; i < 64; i++) //进行初始换位的逆过程 
			text[IP_Table[i] - 1] = text_end[i];


		//CBC模式下的解密
		for (i = 0; i < 64; i++) //前一分组的密文异或当前分组所得明文的二进制放到result中
			result[l][i] = text_out[l][i] ^ text[i];
	}

	for (i = 0; i < (n / 16); i++) //将二进制转成十进制
		for (j = 0; j < 8; j++)
			M[i][j] = result[i][(j * 8) + 0] * 128 + result[i][(j * 8) + 1] * 64 + result[i][(j * 8) + 2] * 32 + result[i][(j * 8) + 3] * 16 + result[i][(j * 8) + 4] * 8 + result[i][(j * 8) + 5] * 4 + result[i][(j * 8) + 6] * 2 + result[i][(j * 8) + 7];
	for (i = 0; i < (n / 16); i++)
		for (j = 0; j < 8; j++)
			plaintext[i * 8 + j] = char(M[i][j]);
	return plaintext;
}
/*
int main() {

	cin >> inputKey;
	cin >> plaintext;

	cout << DESEncrypt_CBC(inputKey, plaintext)<<endl;

	cin >> inputKey;
	cin >> ciphertext;
	cout << DESDecrypt_CBC(inputKey, ciphertext)<<endl;

	return 0;
};
*/


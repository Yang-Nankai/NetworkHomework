#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <fstream>
#include "AES.h"
using namespace std;

#define MAXLEN 1024
int padding;

int wordLength;
int keyword;//密钥有多少个字长
int encryptTimes;//轮数
int beforeTimes;
int keybyte;

//把一个字符转变成整型
static int getIntFromChar(char c) {
    int result = (int)c;
    return result & 0x000000ff;
}

//把4X4数组转回字符串
static void convertArrayToStr(int array[4][4], char* str) {
    int i, j;
    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            *str++ = (char)array[j][i];
}

//把4X4数组放进十六进制存放的字符串 
static void convertArrayToStr16(unsigned char chArray[], unsigned char B[4][4], int l) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            chArray[l] = B[j][i];
            l++;
        }
    }
}

//把字符串写进文件
void writeStrToFile(char* str, int len, char* fileName) {
    FILE* fp;
    fp = fopen(fileName, "wb");
    for (int i = 0; i < len; i++)
        putc(str[i], fp);
    fclose(fp);
}

//从文件中读取字符串
int readStrFromFile(char* fileName, char* str) {
    FILE* fp = fopen(fileName, "rb");
    if (fp == NULL) {
        printf("打开文件出错，请确认文件存在当前目录下！\n");
        exit(0);
    }

    int i;
    //	for (i = 0; i < MAXLEN && (str[i] = getc(fp)) != EOF; i++);
    for (i = 0; i < MAXLEN && !feof(fp); i++) {
        str[i] = getc(fp);
    }
    i--;

    if (i >= MAXLEN) {
        printf("解密文件过大！\n");
        exit(0);
    }

    str[i] = '\0';
    fclose(fp);
    return i;
}

//和偏移向量进行异或
void xorWithiv(unsigned char iv[4][4], unsigned char B[4][4]) {
    for (int i = 0; i <= 3; i++) {
        for (int j = 0; j <= 3; j++) {
            B[i][j] ^= iv[i][j];
        }
    }
}

void setKeyLength(int length) {

    keybyte = length >> 3;//密钥的字节数量
    keyword = keybyte >> 2;//已经有了多少字

    encryptTimes = keyword + 6;
    beforeTimes = encryptTimes - 1;
    wordLength = (encryptTimes + 1) << 2;//总字数，

}

//用于扩展密钥的轮常量
const static unsigned char rcon[13][4] =
{
    {0x01,0x0,0x0,0x0},{0x2,0x0,0x0,0x0},{0x4,0x0,0x0,0x0},{0x8,0x0,0x0,0x0},{0x10,0x0,0x0,0x0},
    {0x20,0x0,0x0,0x0},{0x40,0x0,0x0,0x0},{0x80,0x0,0x0,0x0},{0x1b,0x0,0x0,0x0},{0x36,0x0,0x0,0x0},
    {0x6c,0x0,0x0,0x0},{0xd8,0x0,0x0,0x0},{0xab,0x0,0x0,0x0}
};

//输入密钥，并进行扩展
void setKey(unsigned char keys[][60], string key) {
    int k, i, j, len;
    unsigned char temp[4];
    setKeyLength(256);

    len = key.length();
    for (i = len; i < keybyte; i++) {
        key[i] = 0;
    }
    key[len] = '\0';

    k = 0;
    for (i = 0; i < keyword; i++)
        for (j = 0; j <= 3; j++) {
            keys[j][i] = getIntFromChar(key[k]);
            k++;
        }

    for (i = keyword; i < wordLength; i++) { //后40个word
        if (i % keyword != 0) {//不是4的倍数，word[i] = word[i-4]^word[i-1]
            for (j = 0; j < 4; j++) {
                temp[j] = keys[j][i - 1];
            }

            for (j = 0; j < 4; j++) {
                if (i % keyword == 4 && keyword > 6) {
                    temp[j] = S_BOX[temp[j] / 16][temp[j] % 16];
                }
                keys[j][i] = keys[j][i - keyword] ^ temp[j];
            }
        }

        else {//4的倍数，word[i] = word[i-4]^T(word[i-1]),T代表字节左移一位，S盒字节代换，根据轮数与轮常量进行异或
            for (j = 0; j < 4; j++) {
                temp[j] = keys[j][i - 1];
            }
            for (j = 0; j < 4; j++) {
                temp[j] = keys[(j + 1) % 4][i - 1];
                temp[j] = S_BOX[temp[j] / 16][temp[j] % 16];
                temp[j] = temp[j] ^ rcon[(i / keyword - 1)][j];
                keys[j][i] = keys[j][i - keyword] ^ temp[j];
            }

        }
    }
}

//列混淆运算用到的乘2函数
unsigned char xtime(unsigned char input) {    // x乘法('02'乘法)

    int temp;
    temp = input << 1;

    if (input & 0x80) {
        temp ^= 0x1b;
    }

    return temp;

}

//列混淆运算
void mixcolumn(unsigned char input[][4]) {  //列混淆

    int i, j;
    unsigned char output[4][4];

    for (j = 0; j <= 3; j++)
        for (i = 0; i <= 3; i++)
            output[i][j] = xtime(input[i % 4][j]) //0x02乘法
            ^ (input[(i + 1) % 4][j] ^ xtime(input[(i + 1) % 4][j])) //0x03乘法
            ^ input[(i + 2) % 4][j]  //0x01乘法
            ^ input[(i + 3) % 4][j]; //0x01乘法

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            input[i][j] = output[i][j];

}

//行移位

void shiftrow(unsigned char B[][4]) {

    int i, temp;
    temp = B[1][0];

    for (i = 0; i <= 2; i++)
        B[1][i] = B[1][i + 1];
    B[1][3] = temp;

    for (i = 0; i <= 1; i++) {

        temp = B[2][i];
        B[2][i] = B[2][i + 2];
        B[2][i + 2] = temp;

    }

    temp = B[3][3];
    for (i = 3; i >= 1; i--)
        B[3][i] = B[3][i - 1];
    B[3][0] = temp;

}

//字节变换
void bytesub(unsigned char B[][4]) {

    register int i, j;

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            B[i][j] = S_BOX[B[i][j] / 16][B[i][j] % 16];

}

//逆行移位
void invshiftrow(unsigned char B[][4]) {

    int i, temp;

    temp = B[1][3];

    for (i = 3; i >= 1; i--)
        B[1][i] = B[1][i - 1];
    B[1][0] = temp;

    for (i = 0; i <= 1; i++) {
        temp = B[2][i];
        B[2][i] = B[2][i + 2];
        B[2][i + 2] = temp;
    }

    temp = B[3][0];

    for (i = 0; i <= 2; i++)
        B[3][i] = B[3][i + 1];
    B[3][3] = temp;

}

//逆列混淆运算

void invmixcolum(unsigned char input[][4]) {

    int i, j;
    unsigned char output[4][4];

    for (j = 0; j < 4; j++)
        for (i = 0; i < 4; i++)
            output[i][j] = (xtime(xtime(xtime(input[i % 4][j]))) ^ xtime(xtime(input[i % 4][j])) ^ xtime(input[i % 4][j])) //0x0E乘法
            ^ (xtime(xtime(xtime(input[(i + 1) % 4][j]))) ^ xtime(input[(i + 1) % 4][j]) ^ input[(i + 1) % 4][j]) //0x0B乘法
            ^ (xtime(xtime(xtime(input[(i + 2) % 4][j]))) ^ xtime(xtime(input[(i + 2) % 4][j])) ^ input[(i + 2) % 4][j]) //0x0D乘法
            ^ (xtime(xtime(xtime(input[(i + 3) % 4][j]))) ^ input[(i + 3) % 4][j]); //0x09乘法

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            input[i][j] = output[i][j];

}

//逆字节变换
void invbytesub(unsigned char B[][4]) {

    register int i, j;

    for (i = 0; i <= 3; i++)
        for (j = 0; j <= 3; j++)
            B[i][j] = N_S_BOX[B[i][j] / 16][B[i][j] % 16];

}


int encrypt_cbc(string plaintext, char* ciphertext, string key) {

    unsigned char e, B[4][4], iv[4][4];
    unsigned char keys[4][60];
    int i, j;
    int level, padLength;

    int cArray[4][4];
    int len, k, l;

    len = plaintext.length();

    padLength = 16 - len % 16; //需要填充多少个字符 
    for (i = len; i < padLength + len; i++) {
        plaintext += (char)padLength;
    }
    len += padLength;
    plaintext[len] = '\0';

    setKey(keys, key);

    k = 0;

    for (l = 0; l < len; l += 16) {

        k = l;
        for (i = 0; i <= 3; i++) {
            for (j = 0; j <= 3; j++) {
                B[j][i] = getIntFromChar(plaintext[k]);
                k++;
            }
        }
        if (l == 0) {
            for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                    iv[i][j] = 0;
                }
            }

        }

        xorWithiv(iv, B); //和偏移向量进行异或 

        //轮密钥加 
        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++) {
                B[i][j] ^= keys[i][j];
            }

        for (level = 1; level <= beforeTimes; level++) {    //1到9轮循环
            bytesub(B); //字节代换 
            shiftrow(B);  //行移位 
            mixcolumn(B);  //列混合 

            //这里似乎又是轮密钥加 
            for (i = 0; i <= 3; i++)
                for (j = 0; j <= 3; j++)
                    B[i][j] ^= keys[i][level * 4 + j];
        }

        bytesub(B);               //第10轮循环
        shiftrow(B);

        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++) {
                B[i][j] ^= keys[i][wordLength - 4 + j];
                cArray[i][j] = (int)B[i][j];
            }

        convertArrayToStr(cArray, ciphertext + l);

        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                iv[i][j] = B[i][j];
            }
        }
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
            }
        }
    }
    ciphertext[len] = '\0';
    return len;
}


string decrypt_cbc(char* ciphertext, int len, string key) {

    unsigned char B[4][4], iv[4][4], bef[4][4];
    unsigned char keys[4][60];
    int temp, clen, i, j;
    int level;

    char result[MAXLEN];
    int cArray[4][4];
    unsigned char chArray[MAXLEN];
    int l, k, padLength;
    setKey(keys, key);

    for (l = 0; l < len; l += 16) {
        k = l;
        for (i = 0; i <= 3; i++) {
            for (j = 0; j <= 3; j++) {
                B[j][i] = getIntFromChar(ciphertext[k]);
                bef[j][i] = B[j][i];
                k++;
            }
        }

        if (l == 0) {
            for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                    iv[i][j] = 0;
                }
            }
        }

        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++)
                B[i][j] ^= keys[i][j + wordLength - 4];

        for (level = 1; level <= beforeTimes; level++) {

            invshiftrow(B);
            invbytesub(B);

            for (i = 0; i <= 3; i++)
                for (j = 0; j <= 3; j++)
                    B[i][j] ^= keys[i][wordLength - 4 - level * 4 + j];

            invmixcolum(B);
        }

        invshiftrow(B);
        invbytesub(B);

        for (i = 0; i <= 3; i++)
            for (j = 0; j <= 3; j++) {
                B[i][j] ^= keys[i][j];
            }

        xorWithiv(iv, B);

        for (i = 0; i <= 3; i++) {
            for (j = 0; j <= 3; j++) {
                iv[i][j] = bef[i][j];
                cArray[i][j] = (int)B[i][j];
            }
        }
        convertArrayToStr(cArray, result + l);
    }

    padLength = result[len - 1];
    result[len - padLength] = '\0';
    return (string)result;
}

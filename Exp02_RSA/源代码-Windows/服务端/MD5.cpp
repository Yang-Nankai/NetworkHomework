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

/*
int main() {
	cout << "[INFO] Welcome to NKU_YX MD5.\n" << endl;
	while (true) {
		cout << "[INPUT] Please input your choice: 0 -> message | 1 -> file | 2 -> check | 3 -> Xuebeng | 4 -> quit =>";
		int flag;
		cin >> flag;
		if (flag == 1) {
			FILE* fp;
			char buff[1024];
			string filepath = "";
			cout << "[FILE] Please input your filepath: ";
			cin >> filepath;
			ifstream ifile(filepath.data());
			ostringstream buf;
			char ch;
			while (buf && ifile.get(ch))
				buf.put(ch);
			string input = buf.str();
			cout << "[INFO] the content is: " << input << endl;
			cout << "[MD5] Your file MD5 is: " << md5(input) << endl;
		}
		else if (flag == 2) {
			cout << "[CHECK] Check the file md5 is right ?" << endl;
			string md5_message = "";
			cout << "[INFO] Please input your md5: " << endl;
			cin >> md5_message;
			cout << "[FILE] Please input your filepath: " << endl;
			string filepath = "";
			cin >> filepath;
			ifstream ifile(filepath.data());
			ostringstream buf;
			char ch;
			while (buf && ifile.get(ch))
				buf.put(ch);
			string input = buf.str();
			cout << "[MD5] Your file MD5 is: " << md5(input) << endl;
			if (md5(input) == md5_message) {
				cout << "[RIGHT] Check right! ! !" << endl;
			}
			else {
				cout << "[WRONG] Check wrong! ! !" << endl;
			}
		}
		else if (flag == 0) {
			cout << "[INFO] Please input your message: ";
			string message = "";
			cin.clear();
			cin.ignore();
			getline(cin, message);
			cout << "[MD5] Your input message md5 is: " << md5(message) << endl;
		}
		else if (flag == 4) {
			cout << "[BYE] Bye-Bye, hope to see you again~" << endl;
			break;
		}
		else if (flag == 3) {
			//ѩ������
			cout << "[INFO] Now start Xuebeng test: " << endl;
			string message = "0123456789ABCDEFG";  //������֤ѩ�����Ե��ַ���
			string newMessage;
			int sum = 0;
			int diff = 0;
			for (int i = 1; i <= 128; i++) {
				diff = 0;
				newMessage = message;
				changeOneBit(newMessage[(i - 1) / 8], i % 8);
				diff = diff_bit(md5(message), md5(newMessage));
				sum += diff;
				cout << diff << " ";
				if (i % 16 == 0)
					cout << endl;
			}
			cout << "[INFO] The average diff bit is => " << sum / 128.0 << endl;

		}
		else {
			cout << "[INFO] Your input wrong! Please again!" << endl;
			continue;
		}
	}
	return 0;

}
*/
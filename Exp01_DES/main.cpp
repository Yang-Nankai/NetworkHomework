#include <iostream>
#include "server.h"
#include "client.h"

using namespace std;

int main() {
	
	int choice = 0;
	cout << "1.服务器 2.客户端" << endl;
	cin >> choice;
	if (choice == 1) {
		server();
	}
	else if (choice == 2) {
		client();
	}
	else {
		cout << "输入错误!!!" << endl;
		exit(0);
	}
	return 0;
}

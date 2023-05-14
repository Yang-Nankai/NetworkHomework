#include<iostream>
#include<string>
#include"define.h"

using namespace std;

void usage() {
	cerr << "YangMD5 [ -s string ] [ -f file ] [ -c md5 file ] [ -b file1 file2 ]"
		<< " -s string" << endl
		<< "			the input string " << endl
		<< " -f file" << endl
		<< "			the input filepath" << endl
		<< " -c md5 file" << endl
		<< "			input the md5 and file to check the file" << endl
		<< " -b file1 file2" << endl
		<< "			input the file1 and file2 to check the same" << endl;
}

int main(int argc, char** argv) {
	for (size_t i = 1; i < argc; i++) {
		if (string(argv[i]) == "-s") {
			if (argc > 3) {
				usage();
				exit(1);
			}
			string tmps = string(argv[i + 1]);
			cout<<"String MD5: " << md5(tmps) << endl;
		}
		else if (string(argv[i]) == "-f") {
			if (argc > 3) {
				usage();
				exit(1);
			}
			string filepath = string(argv[i + 1]);
			ifstream ifile(filepath.data());
			ostringstream buf;
			char ch;
			while (buf && ifile.get(ch))
				buf.put(ch);
			string input = buf.str();
			cout << "File MD5: " << md5(input) << endl;
		}
		else if (string(argv[i]) == "-c") {
			if (argc > 4) {
				usage();
				exit(1);
			}
			string imd5 = string(argv[i + 1]);
			string filepath = string(argv[i + 2]);
			ifstream ifile(filepath.data());
			ostringstream buf;
			char ch;
			while (buf && ifile.get(ch))
				buf.put(ch);
			string input = buf.str();
			string fmd5 = md5(input);
			string flag = strcmp(fmd5.c_str(), imd5.c_str()) ? "false" : "true";
			cout << "Input MD5: " << imd5 << endl
				<< "File  MD5: " << fmd5 << endl
				<< flag << endl;
		}
		else if (string(argv[i]) == "-b") {
			if (argc > 4) {
				usage();
				exit(1);
			}
			string filepath1 = string(argv[i + 1]);
			string filepath2 = string(argv[i + 2]);
			ifstream ifile1(filepath1.data());
			ostringstream buf1;
			char ch;
			while (buf1 && ifile1.get(ch))
				buf1.put(ch);
			string input1 = buf1.str();
			string f1md5 = md5(input1);
			ifstream ifile2(filepath2.data());
			ostringstream buf2;
			while (buf2 && ifile2.get(ch))
				buf2.put(ch);
			string input2 = buf2.str();
			string f2md5 = md5(input2);
			string flag = strcmp(f1md5.c_str(), f2md5.c_str()) ? "false" : "true";
			cout << "File1 MD5: " << f1md5 << endl
				<< "File2 MD5: " << f2md5 << endl
				<< flag << endl;
		}
		else if(string(argv[i]) == "-h"){
			usage();
			exit(1);
		}
	}
	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fstream>
#include <iostream>
#include <fcntl.h>

using namespace std;
const int SERVER_PORT = 8888;
const int BUFFER_LEN = 1024 * 64;
const char *PATH_PUB_KEY = "key.pub";
const char *PATH_SIGN = "message.sign";
const char *PATH_MESSAGE = "message";

int startConn(char *server_addr) {
	int sockfd, portno, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[1024 * 64];
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	server = gethostbyname(server_addr);
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr,
		(char *)&serv_addr.sin_addr.s_addr,
		server->h_length);
	serv_addr.sin_port = htons(SERVER_PORT);
	connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr));
	return sockfd;
}

string getMsg(int fd) {
	char buffer[BUFFER_LEN];
	read(fd, buffer, BUFFER_LEN);
	return string(buffer);
}

void writeMsg(int fd, string msg) {
	write(fd, msg.c_str(), msg.size());
}

void readKey(const char *_path, BIGNUM *n, BIGNUM *x) {
	ifstream file;
	file.open(_path);
	string n_str, x_str;
	file >> n_str >> x_str;
	BN_dec2bn(&n, n_str.c_str());
	BN_dec2bn(&x, x_str.c_str());
	file.close();
}

void messageToBNC(const char *msg, BIGNUM *x) {
	string message = string(msg);
	const string dict = "0123456789abcdef";
	string hex = "";
	for (int i = 0; i < message.size(); i++){
		hex += dict[message[i]/16];
		hex += dict[message[i]%16];
	}
	BN_hex2bn(&x, hex.c_str());
}

void savesign(const char *path, BIGNUM *bn, const char *msg, const char *M_path){
	ofstream file;
	file.open(path);
	string sign = string(BN_bn2dec(bn));
	file.write(sign.c_str(), sign.size());
	file.close();
	file.open(M_path);
	string mess = string(msg);
	file.write(msg, mess.size());
	file.close();
}

int main(int argc, char *argv[]) {
	if(argc == 4) {
		int serverFD = startConn(argv[1]);
		cout << "Podaj hasło: " << endl;
		string msg;
		cin >> msg;
		writeMsg(serverFD, msg);

		//Odpowiedz
		msg = getMsg(serverFD);

		if(msg[0] == 'Y') {
			cout << "OK" << endl;

			BN_CTX *ctx;
			ctx = BN_CTX_new();

			BIGNUM *n, *e, *x, *r, *d, *r1;
			n = BN_new();
			e = BN_new();
			d = BN_new();
			r1 = BN_new();
			//wartosc wiadomosci w bn
			x = BN_new();

			readKey(argv[2], n, e);

			messageToBNC(argv[3], x);
			r = BN_new();
			BN_rand_range(r, n);
			BN_mod_exp(d, r, e, n, ctx);
			BN_mod_mul(x, x,d, n,ctx);
			writeMsg(serverFD, string(BN_bn2dec(x)));
			//cout << string(BN_bn2dec(x)) << endl;

			string blindSignature = getMsg(serverFD);
			//cout << "#####################\n";
			//cout << blindSignature << endl;
			BN_dec2bn(&x, blindSignature.c_str());
			BN_mod_inverse(r1 ,r,n,ctx);
			BN_mod_mul(x,x,r1,n,ctx);
			//cout << string(BN_bn2dec(x)) << endl;
			savesign(PATH_SIGN, x, argv[3], PATH_MESSAGE);
			BN_CTX_free(ctx);
		} else {
			cout << "Wrong password" << endl;
		}

		close(serverFD);
	} else {
		cout << "Za mała liczba argumentów!" << endl;
	}
	return 0;
}

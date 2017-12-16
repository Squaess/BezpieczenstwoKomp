#include <iostream>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "src/argon2.h"

const int HASH_LEN = 32;
#define SALTLEN 16
const char *HASH_PATH = "hash";
const char *PATH_PRIV_KEY = "key";
const char *PATH_PUB_KEY = "key.pub";

const int SERVER_PORT = 8888;
const int BUFFER_SIZE = 1024 * 64;
const int PASSWORD_SIZE = 12;

using namespace std;

string gen_random(int len) {
	srand (time(NULL));
	static const char dictionary[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	string s = "";
	for (int i = 0; i < len; ++i)
		s += dictionary[rand() % (sizeof(dictionary) - 1)];
	return s;
}

void saveHash(const char *_path, uint8_t* _hash, int len) {
	ofstream file;
	file.open(_path, ios::binary);
	file.write((const char*)_hash, len);
	file.close();
}

void readHash(const char *_path, uint8_t* _hash, int len) {
	ifstream file;
	file.open(_path, ios::binary);
	file.read((char *)_hash, len);
	file.close();
}

void countHash(string text, uint8_t *_hash, int hashlen) {

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

	uint8_t pwd[text.size()];
	for(int i = 0; i < text.size(); i++) {
		pwd[i] = text[i];
	}

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

	argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, text.size(), salt, SALTLEN, _hash, hashlen);
}

void saveKey(const char *_path, const BIGNUM *n, const BIGNUM *x) {
	ofstream file;
	file.open(_path);
	file << BN_bn2dec(n) << " " << BN_bn2dec(x);
	file.close();
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

void setup(int keySize) {
	// int keySize = 1024;
	const clock_t begin_time = clock();

	unsigned long ee = RSA_F4;
	BIGNUM *bne = NULL;
	bne = BN_new();
	BN_set_word(bne,ee);

	RSA *r = RSA_new();
	RSA_generate_key_ex(r, keySize, bne, NULL);

	BIO *bp_public = NULL, *bp_private = NULL;

	const BIGNUM *p, *q, *n, *e, *d;
	p = BN_new();
	q = BN_new();
	n = BN_new();
	e = BN_new();
	d = BN_new();
	// RSA_get0_factors(r, &p, &q);
	RSA_get0_key(r, &n, &e, &d);
	saveKey(PATH_PUB_KEY, n, e);
	saveKey(PATH_PRIV_KEY, n, d);
	ofstream file;
	file.open("data", ios_base::app);
	file <<"GEN | Key size: " << keySize << " " << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;
	file.close();
	string passwd = gen_random(PASSWORD_SIZE);
	//string passwd = "Haslohaslo12";
	cout << "Generated password: " << passwd << endl;

	const int HASH_LEN = 32;
	uint8_t _hash[HASH_LEN];
	countHash(passwd, _hash, HASH_LEN);
	//cout << "HASH: " << _hash << endl;
	saveHash(HASH_PATH, _hash, HASH_LEN);
}

socklen_t clilen;
struct sockaddr_in serv_addr, cli_addr;
int sockfd, fdsock;

int startConn() {
	char buffer[BUFFER_SIZE];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(SERVER_PORT);
	if (bind(sockfd, (struct sockaddr *) &serv_addr,
              sizeof(serv_addr)) < 0) {
		return -2;
	}

	listen(sockfd,5);
     clilen = sizeof(cli_addr);
}

int getNextClient() {
	fdsock = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	return fdsock;
}

void writeMsg(int fd, string msg) {
	write(fd, msg.c_str(), msg.size());
}

string getMsg(int fd) {
	char buffer[BUFFER_SIZE];
	read(fd, buffer, BUFFER_SIZE);
	return string(buffer);
}

bool check(string msg) {
	msg = msg.substr(0, PASSWORD_SIZE);
	// Hash otrzymanej wiadomosci
	uint8_t msg_hash[HASH_LEN];

	// Pobrany hash z pliku
	uint8_t hash[HASH_LEN];

	//msg = msg.substr(0, PASSWORD_SIZE);
	countHash(msg, msg_hash, HASH_LEN);
	readHash(HASH_PATH, hash, HASH_LEN);
	//cout <<"Message: " << msg_hash << endl;
	//cout <<"READLHA: " << hash << endl;
	for (int i = 0; i < HASH_LEN; i++){
		if(hash[i] != msg_hash[i]){
			cout << "REAL: "<<hash<<endl;
			cout << "YOUR: "<<msg_hash<<endl;
			cout << msg << endl;
			return false;
		}
	}
	return true;
}

void signService(int clientFD) {
	string msg = getMsg(clientFD);
	if(check(msg)){
		writeMsg(clientFD, "Y");
		cout << "authentication confirmed" << endl;
		const clock_t begin_time = clock();

		BN_CTX *ctx;
		ctx = BN_CTX_new();

		BIGNUM *n, *d, *x, *gcd;
		n = BN_new();
		d = BN_new();
		x = BN_new();

		readKey(PATH_PRIV_KEY, n, d);
		gcd  = BN_new();

		string toCompute = getMsg(clientFD);
		BN_dec2bn(&x, toCompute.c_str());
		//cout << "Obliczam\n" << string(BN_bn2dec(x)) << endl;
		BN_gcd(gcd, x, n, ctx);
		if(BN_is_one(gcd)){
			BN_mod_exp(gcd, x, d, n, ctx);

			string send = string(BN_bn2dec(gcd));
			//cout << "#####################\n";
			//cout << send << endl;
			writeMsg(clientFD, send);
			ofstream file;
			file.open("data", ios_base::app);
			file <<"Sign: Key size 8192 " << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;
			file.close();

		} else {

			cout << "Not in Z_n*" << endl;
		}
		BN_CTX_free(ctx);
	} else {
		writeMsg(clientFD, "N");
		cout << "Message authentication failed" << endl;
		return;
	}
}

int main(int argc, char **argv) {

	if (argc > 2 && string(argv[1]) == "setup") {
		setup(atoi(argv[2]));
	} else if (argc > 1 && string(argv[1]) == "signservice") {
		cout << "start sign service" << endl;
		startConn();
		while(true) {
			int clientFD = getNextClient();
			if (clientFD < 0) {
				cout << "Connection problem " << clientFD << endl;
				return 1;
			}
			cout << "connected" << endl;
			signService(clientFD);
			close(clientFD);
		}
	}

	return 0;
}

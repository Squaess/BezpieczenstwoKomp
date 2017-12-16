#include <iostream>
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

using namespace std;
const char *PATH_SIGN = "message.sign";
const char *PATH_MESSAGE = "message";

const char *PATH_PRIV_KEY = "key";

string readMessage(const char *path){
    ifstream file;
	file.open(path);
	string msg;
	file >> msg;
	file.close();
    return msg;
}

void readSign(BIGNUM *bn, const char *path){
    ifstream file;
    file.open(path);
    string x;
    file >> x;
    BN_dec2bn(&bn, x.c_str());
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

void messageToBNC(string msg, BIGNUM *x) {

	const string dict = "0123456789abcdef";
	string hex = "";
	for (int i = 0; i < msg.size(); i++){
		hex += dict[msg[i]/16];
		hex += dict[msg[i]%16];
	}
	BN_hex2bn(&x, hex.c_str());
}

int main(int argc, char const *argv[]) {
    string message = readMessage(PATH_MESSAGE);
    cout << message << endl;

    const clock_t begin_time = clock();

    BN_CTX *ctx;
    ctx = BN_CTX_new();

    BIGNUM *bn, *n, *d, *x, *first;
    bn = BN_new();
    n = BN_new();
    d = BN_new();
    x = BN_new();
    first = BN_new();

    readSign(bn, PATH_SIGN);
    //cout << string(BN_bn2dec(bn)) << endl;
    readKey(PATH_PRIV_KEY, n, d);

    messageToBNC(message, x);

    BN_mod_exp(first, x, d, n, ctx);

    if(BN_cmp(first, bn) == 0){
        cout << "OK" << endl;
    } else {
        cout << "nope" <<endl;
    }
    ofstream file;
    file.open("data", ios_base::app);
    file <<"Verify: Key size 8192 " << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;
    file.close();
    BN_CTX_free(ctx);

    return 0;
}

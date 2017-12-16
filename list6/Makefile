all: server client verify

client: bclient.cpp
	g++ -o bclient bclient.cpp -lcrypto -lpthread

server: bserver.cpp
	g++ -lcrypto -lpthread -o bserver bserver.cpp src/*.c src/blake2/blake2b.c

verify: verify.cpp
	g++ -lcrypto -lpthread -o verify verify.cpp src/*.c src/blake2/blake2b.c
clean:
	rm -f bserver
	rm -f bclient
	rm -f verify

remake: clean all

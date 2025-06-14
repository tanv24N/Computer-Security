g++ -w fscrypt.cc -c -o fscrypt.o
g++ -w main.cc fscrypt.o -o my_program -lcrypto
./my_program
#include <stdio.h>
#include <stdlib.h>

void confuse() {
        printf("What should I do here...?\n");
}

void prompt(){
	char buf[128];

	gets(buf);
	printf("Input: %s\n", buf);

}

int main(){
	confuse();
	prompt();
	return 0;
}

void target(){
	printf("I am sorry that you just got pwned!\n");
	exit(0);
}

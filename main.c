#include <stdio.h>

int main (int argc, char ** argv) {
    char buffer[24];

    printf("Enter name: ");
    gets(buffer);
    printf("Hello, %s\n", buffer);
    }
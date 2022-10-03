#include <payload.hpp>

#include <stdio.h>

// Everything inside this macro is hidden 
POLYV_HIDDEN_SECTION (

/**
 *  Print to console all program arguments
 */
int POLYV_ENCRYPTED payload(int argc, char* argv[]) {

    printf("PAYLOAD: \n");
    for (int i = 0; i < argc; i++)
        printf("\t[%i] %s\n", i, argv[i]);

    return 0;
}

)
#include <unicorn/unicorn.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "AflUnicornEngine.h"

int main(int argc, char* argv[]){
    AflUnicornEngine afl = AflUnicornEngine(argv[1]);
}
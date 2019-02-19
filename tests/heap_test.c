#include <stdlib.h>

int main(){
    char* m1 = malloc(0x300);
    char* m2 = malloc(0x20010);
    
    m1[0x300-1] = 0;
    m2[0x20010-1] = 0;
    
    free(m1);
    free(m2);
}
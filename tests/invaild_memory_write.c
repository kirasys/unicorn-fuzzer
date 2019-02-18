#include <stdio.h>

int main(){
    printf("Invaild memory write!");
    
    char *addr = (char*)0;
    addr[0] = 1;
}
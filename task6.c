#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr1 = realloc(NULL, 100); 
    void *ptr2 = realloc(ptr1, 0);   

    printf("ptr1 address -> %p\n", ptr1);
    printf("ptr2 address -> %p\n", ptr2); 

    return 0;
}

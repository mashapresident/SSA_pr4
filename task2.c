#include <stdio.h>
#include <stdlib.h>

int main() {
    int xa = 100000;
    int xb = 100000;
    int num = xa * xb; 
    printf("Result of multiplication: %d\n", num);

    size_t safe_num = (size_t)num; 
    void *ptr = malloc(safe_num); 
    if (ptr == NULL) {
        printf("Memory allocation failed due to overflow or insufficient memory.\n");
    } else {
        printf("Memory allocated successfully!\n");
        free(ptr);
    }

    return 0;
}

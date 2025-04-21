#include <stdlib.h>
#include <stdio.h>
#include <malloc.h> 
struct sbar {
    int a;
    char b;
};

int main() {
    struct sbar *ptr = calloc(1000, sizeof(struct sbar));
    struct sbar *newptr = reallocarray(ptr, 500, sizeof(struct sbar));
    if (!newptr) {
        printf("reallocarray\n");
        free(ptr);
        return 1;
    }
    printf("new pointer address -> %p \n", newptr);
    free(newptr);
    return 0;
}

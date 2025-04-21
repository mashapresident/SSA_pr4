#include <stdio.h>
#include <stdlib.h>

int main() {
    size_t size = 10;
    void *ptr = malloc(size);

    if (!ptr) {
        printf("step 1 -> initial allocation failed;(\n");
        return 1;
    }

    size_t new_size = size * ((size_t) - 1);
    void *new_ptr = realloc(ptr, new_size);
    if (new_ptr == NULL) {
        printf("step 2 -> realloc failed;(\n");
        free(ptr);
    } else {
        printf("realloc succeeded!\n");
        free(new_ptr); 
    }

    return 0;
}

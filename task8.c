#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 64      
#define POOL_SIZE  1024    

typedef struct FreeBlock {
    struct FreeBlock* next;
} FreeBlock;

typedef struct {
    uint8_t* memory_pool;   
    FreeBlock* free_list;   
    size_t block_size;
    size_t total_blocks;
} Allocator;

void allocator_init(Allocator* allocator, size_t block_size, size_t pool_size) {
    allocator->block_size = block_size;
    allocator->total_blocks = pool_size / block_size;
    allocator->memory_pool = malloc(pool_size);

    if (!allocator->memory_pool) {
        printf("malloc");
        exit(1);
    }
    allocator->free_list = NULL;
    for (size_t i = 0; i < allocator->total_blocks; i++) {
        FreeBlock* block = (FreeBlock*)(allocator->memory_pool + i * block_size);
        block->next = allocator->free_list;
        allocator->free_list = block;
    }
}

void* allocate(Allocator* allocator) {
    if (!allocator->free_list) {
        return NULL;  // Пам’ять закінчилася
    }

    FreeBlock* block = allocator->free_list;
    allocator->free_list = block->next;
    return (void*)block;
}

void deallocate(Allocator* allocator, void* ptr) {
    if (!ptr) return;
    FreeBlock* block = (FreeBlock*)ptr;
    block->next = allocator->free_list;
    allocator->free_list = block;
}

void allocator_destroy(Allocator* allocator) {
    free(allocator->memory_pool);
    allocator->memory_pool = NULL;
    allocator->free_list = NULL;
}
int main() {
    Allocator allocator;
    allocator_init(&allocator, BLOCK_SIZE, POOL_SIZE);

    void* ptr1 = allocate(&allocator);
    void* ptr2 = allocate(&allocator);

    printf("Allocated block at %p\n", ptr1);
    printf("Allocated block at %p\n", ptr2);

    deallocate(&allocator, ptr1);
    deallocate(&allocator, ptr2);

    void* ptr3 = allocate(&allocator); // reuse!
    printf("Reused block at %p\n", ptr3);

    allocator_destroy(&allocator);
    return 0;
}

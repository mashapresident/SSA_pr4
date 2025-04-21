#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(){
	size_t max_val = (size_t) - 1;
	printf("max val of size_t -> %zu \n", max_val);
	void *ptr = malloc(max_val);
	if(ptr == NULL){
		printf("memory allocation failed\n");
		return 1;
	}
	else{
		printf("memory allocated without any trouble;P\n");
		free(ptr);
	}
	return 0;
}


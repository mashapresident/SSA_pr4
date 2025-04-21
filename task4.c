#include <stdio.h>
#include <stdlib.h>
int main(){
	void *ptr = NULL;
	while(1){
	if (!ptr){
		free(ptr);
		ptr = malloc(sizeof(void *));
		printf("ptr locates at %p\n", ptr);
	}
	}
	free(ptr);
	return 0;
}

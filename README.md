## Завдання 1

### Текст завдання
Скільки пам’яті може виділити malloc(3) за один виклик?
Параметр malloc(3) є цілим числом типу даних size_t, тому логічно максимальне число, яке можна передати як параметр malloc(3), — це максимальне значення size_t на платформі (sizeof(size_t)). У 64-бітній Linux size_t становить 8 байтів, тобто 8 * 8 = 64 біти. Відповідно, максимальний обсяг пам’яті, який може бути виділений за один виклик malloc(3), дорівнює 2^64. Спробуйте запустити код на x86_64 та x86. Чому теоретично максимальний обсяг складає 8 ексабайт, а не 16?
____
### *Реалізація*
```
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
```
>$ gcc task1.c -o t1
>
>$ /t1
>
>max val of size_t -> 18446744073709551615
>
>memory allocation failed

____
### *Пояснення*
size_t на 64-бітній системі — 8 байтів (тобто 64 біти), отже, максимально можливе значення — 2^64 - 1 (≈ 18.4 ексабайт).

Але архітектура x86_64 обмежена користувацьким простором адресації до 48 біт. Отже, реально виділити можна до 2^48 (≈ 256 ТБ). Саме тому не 16 ексабайт.

## Завдання 2

### Текст завдання
Що станеться, якщо передати malloc(3) від’ємний аргумент? Напишіть тестовий випадок, який обчислює кількість виділених байтів за формулою num = xa * xb. Що буде, якщо num оголошене як цілочисельна змінна зі знаком, а результат множення призведе до переповнення? Як себе поведе malloc(3)? Запустіть програму на x86_64 і x86.
____
### *Реалізація*
```
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

```

>$ gcc task2.c -o t2
>
>$ /t2
>
>Result of multiplication: 1410065408
>
>Memory allocated successfully!

____
### *Пояснення*
Якщо результат переповнення — від’ємне число, воно буде неявно перетворене до size_t, тобто до дуже великого позитивного значення

## Завдання 3

### Текст завдання
Що станеться, якщо використати malloc(0)? Напишіть тестовий випадок, у якому malloc(3) повертає NULL або вказівник, що не є NULL, і який можна передати у free(). Відкомпілюйте та запустіть через ltrace. Поясніть поведінку програми.
____
### *Реалізація*
```
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(0); 
    if (ptr == NULL) {
        printf("malloc(0) returned NULL\n");
    } else {
        printf("malloc(0) returned a non-NULL pointer\n");
        free(ptr); 
    }

    return 0;
}

```
>$ gcc task3.c -o t3
>
>$ /t3
>
>malloc(0) returned a non-NULL pointer
>
>$ ltrace /t3
>
>malloc(0) = 0x55bd8d532a0
>puts ("malloc(0) returned a non-NULL po"... malloc(0) returned a non-NULL pointer) = 38
>free(0x55bd8d532a0) = ‹void>
>+++ exited (status 0) +++

____
### *Пояснення*
"If the size of the space requested is zero, the behavior is implementation-defined: either a null pointer is returned, or the behavior is as if the size were some nonzero value." Іншими словами, malloc(0) може повернути не-NULL, тобто валідний вказівник — і це абсолютно нормальна поведінка згідно зі стандартом C.
____
## Завдання 4

### Текст завдання
Чи є помилки у такому коді?
void *ptr = NULL;
while (<some-condition-is-true>) {
    if (!ptr)
        ptr = malloc(n);
    [... <використання 'ptr'> ...]
    free(ptr);
}

____
### *Реалізація*
```
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
```
>$ gcc task4.c -o t4
>
>$ /t4
>
>ptr locates at 0x5f52685132a0

____
### *Пояснення*
ptr виділяється тільки один раз, але звільняється кожну ітерацію. На наступному циклі — ptr уже не валідний, але не оновлюється (бо if (!ptr) вже не істинне)

## Завдання 5

### Текст завдання
Що станеться, якщо realloc(3) не зможе виділити пам’ять? Напишіть тестовий випадок, що демонструє цей сценарій.
____
### *Реалізація*
```
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

```
>$ gcc task5.c -o t5
>
>$ /t5
>
> step 2 -> realloc failed; 

____
### *Пояснення*
Перший етап виділення памʼяті пройшов успішно, що є очевидним, адже 10 - "адекватний" розмір для подібної операції. Під час "перевиділення" памʼяті ми задали надзвичайно великий параметр, що спричинило порушення роботи програми, про що нам каже стрічка "step 2 -> realloc failed;"



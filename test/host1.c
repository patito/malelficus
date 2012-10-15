#include <stdio.h>

int main()
{
    int i;
    printf("simple host program.\n");
    
    for (i = 0; i < 10; i++) {
        printf("i = %d\n", i);
        if (i == 7) printf("sete\n");
    }
    return 0;
}


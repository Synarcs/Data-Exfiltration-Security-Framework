#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <time.h>

#define DEBUG(x, ...) do { } while(0);

typedef struct SocketHandler {
    uint64_t fd;
    union {
        uint64_t files[100];
    };
} SocketHandler;

int main() {
    srand(time(NULL));
    const int mx = rand();

    printf("%d ", mx);
    int * arr = (int *) malloc(sizeof(int) * mx);
    int *spawarr_cpy = (int *) malloc (sizeof(int) * mx);
    int ** buffer = (int **) malloc(sizeof(int) * mx);
    const int size = 10;

    for (int i=0; i < size; i++) *(arr + i) = (1 << i) % 4 == 0 ? 1 << i : i >> 1; 

    memcpy(spawarr_cpy, arr, size * sizeof(int));
    for (int i=0; i < size; i++) printf("%d ", *(spawarr_cpy + i));

    for (int i=0; i < size; i++)  {
        buffer[i] = (int *) malloc(sizeof(int) * (int) size / 2);
        for (int j=0; j < (int) size / 2; j++) *(*(buffer + i) + j) = j;
    }

    free(buffer);
    free(arr);

    return 0;
}
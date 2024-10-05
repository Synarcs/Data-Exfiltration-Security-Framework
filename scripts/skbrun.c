#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define __print_handler(x, y, ...) __GENERIC(x, \
    __uint16_t: printf("%u\n", y), \
    __uint32_t: printf("%u\n", y), \
    default: printf("Generic type not processed\n") \
);

typedef struct Proc {
    int processId;
    struct Proc *next;
    void * (*handler) (void *, void *, int)
} procMap;

void *handler (void *start, void *end, int size) {

    for (int i = 0; i < size; i++){
        if ((void *)((procMap *) start + sizeof(procMap) * i) <= (void *)((procMap *) end + sizeof(procMap))) {
            procMap curr = *((procMap *)start + sizeof(procMap) * i);
            printf("Process ID: %d\n", curr.processId);
        }
    }

    struct Proc proc[10];
    void (* make)(void *, void *, int) = &handler;
    for (int i=0; i < (sizeof(proc) /  sizeof(proc[0])); i++){
        proc[i] = (procMap) {
            .processId = 1 << 20, 
            .next = NULL,
            .handler = make,
        };
    }
    return (void *) start + sizeof(procMap) * size;
}

int main(void){
    procMap *proc;
    proc = (struct procMap *) malloc(sizeof(procMap));

    int ** mem  = (int **) malloc (sizeof(int *) * 10);

    for (int i=0; i < 10; i++){
        mem[i] = (int *) malloc(sizeof(int) * 10);
        int sz = (int) sizeof(mem[i]) / sizeof(mem[i][0]);
        for (int j = 0; j < sz; j++ ){
            mem[i][j] = 1 + (i << j) - 1;
        }
    }
    procMap map[10];
    int size = (int) sizeof(map) / sizeof(map[0]);

    printf("the size is %d", size);

    procMap *start = &map;
    procMap *end = start + sizeof(procMap) * size;
    for (int i = 0; i < size; i++){
        *(start + sizeof(procMap) * i) = (procMap) {
            .processId = (1 << i) - 1,
            .next = NULL,
            .handler = &handler
        };
    }    

    handler((void *) start, (void *) end, size);

    for (int i = 0; i < 10; i++) free(mem[i]);
    free(mem);
    free(proc);

    return 0;
}
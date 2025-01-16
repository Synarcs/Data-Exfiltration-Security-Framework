
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define DEBUG(x)   do \
                    printf("%d", x) \ 
                   while(0) 

#define __print_handler(x, y, ...) __GENERIC(x, \
    __uint16_t: printf("%u\n", y), \
    __uint32_t: printf("%u\n", y), \
    default: printf("Generic type not processed\n") \
);

enum ProcHandler { MEMFLOW = 1 };

typedef __uint8_t __u8;
typedef __uint16_t __u16;

typedef struct Proc {
    int processId;
    struct Proc *next;
    void * (*handler) (void *, void *, int);
    void * (*handler_status) (void *, enum ProcessHandler);
    __u8 *  (*resp_handler) (void *, void *, __u16 *);
} procMap, threadParentMaps;

typedef struct actions {
    union  {
        void * (* add) (struct handler *, int *rootl);
        void * (* init) (int *root);
    };
} act;

typedef struct handler {
    int *data; 
    struct handler *next; 
    union {
        int (*size) (struct handler *);
    };
} __attribute__((packed)) List;

int * processMap (int *arr, int (*map) (int ), void *end, int size) {
    for (int i=0; i < size; i++) {
        if ((void *) arr + i < end) 
            arr[i] = map(arr[i]); 
    }
    return arr;
}

void * handler (void *start, void *end, int size) {

    for (int i = 0; i < size; i++){
        if ((void *)((procMap *) start + sizeof(procMap) * i) <= (void *)((procMap *) end + sizeof(procMap))) {
            procMap curr = *((procMap *)start + sizeof(procMap) * i);
            printf("Process ID: %d\n", curr.processId);
        }
    }

    struct Proc proc[10];
    
    void * (* make)(void *, void *, int) = &handler;
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
    procMap *proc = (procMap *) malloc(sizeof(procMap));

    if (!proc) 
        return 0;
    size_t processNodesSize = sizeof(proc);
    int ** mem  = (int **) malloc (sizeof(int *) * 10);
    const int sz = 1 << 2;

    for (int i=0; i < 10; i++){
        mem[i] = (int *) malloc(sizeof(int) * 10);
        int sz = (int) sizeof(mem[i]) / sizeof(mem[i][0]);
        for (int j = 0; j < sz; j++ )
            mem[i][j] = 1 << i - j;
    }

    procMap map[10];
    int size = (int) sizeof(map) / sizeof(map[0]);

    printf("the size is %d", size);

    procMap *start = &map[0];
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
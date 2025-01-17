#include <liburing/io_uring.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define DEBUG_EVENT(ev, ...) printf("%d", ev)

typedef struct BufferEventInfo {
    char *event;
    uint64_t fd;
} __attribute__((packed)) BufferEventInfo;

typedef struct BufferPollEvent {
    int event_id;
    union {
        struct event_head *BufferEventInfo;
    };
} __attribute__((packed)) BufferPollEvent;

int main(void) {
    const int max_ring_size = 10;
    struct BufferPollEvent * ring[max_ring_size];
    for (int i=0; i < max_ring_size; i++) 
        ring[i] = (struct BufferPollEvent *)malloc(sizeof(struct BufferPollEvent));
    
    for (int i=0; i < max_ring_size; i++)  {
        size_t ring_event_size = sizeof(ring[i]);
        printf("%ld \n" , ring_event_size);
    }
    return 0;
}
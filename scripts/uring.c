#include <liburing/io_uring.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define DEBUG_EVENT(ev, ...) printf("%d", ev)

typedef struct BufferEventInfo {
    char *event;
    uint64_t fd;
    int (*getFd) ();
    struct BufferEventInfo * (*getEventInfo) (struct BufferEventInfo *);
} __attribute__((packed)) BufferEventInfo;

typedef struct rcu_event_head {
    struct BufferEventInfo *data;
    struct rcu_event_head *left;
    struct rcu_event_head *right;
} __attribute__((packed)) rcu_event_head;

typedef struct BufferPollEvent {
    int event_id;
    union {
        struct rcu_event_head *event;
    };
} __attribute__((packed)) BufferPollEvent;

int main(void) {
    struct rcu_event_head *event_rcu_node = &(struct rcu_event_head) {
        .data = &(struct BufferEventInfo) {
            .event = "root",
            .fd = 0xff,
        },
    };
    event_rcu_node->left = NULL;
    event_rcu_node->right = NULL;

    if (event_rcu_node->data != NULL) {
        printf("Event fd info %lx" , event_rcu_node->data->fd);
    }
    return 0;
}
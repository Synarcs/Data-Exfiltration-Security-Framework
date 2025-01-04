#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <liburing/io_uring.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define MAX_EVENTS 5 
static int READ_SIZE = 10;

#ifndef DRAIN
    #define DRAIN(X, QUEUE)      \
            do {                 \
                QUEUE[X] = '\0'; \
                X++;             \
            }while (X != 0);    
#endif

static volatile const int  QUEUE_SIZE = 1024;

extern struct task_struct *  __fd_info(int fd);

int main(void) {
    struct  epoll_event event, events[MAX_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = 2;

    int fd = epoll_create1(0);

    int val = fcntl(fd, F_GETFL);
    int dup_val_fd = fcntl(fd, F_DUPFD);

    int sock_fd;
    if (sock_fd = socket(AF_INET, SOCK_DGRAM, 0) < 0){
        perror("Error binding socket");
    }

    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t proc = getpid();

    printf("Process Information %u %u %u \n", uid, gid, proc);
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {}

    printf("File descriptor open information: %d\n", val);

    if (epoll_ctl(fd, EPOLL_CTL_ADD, 0, &event)) {
        perror("epoll_ctl");
        return 1;
    }

    printf("Process ID adding epoll events over POLL STDIN: %d\n", proc); 
    int event_count = 0;
    size_t bytes_read;  char read_buffer[READ_SIZE + 1]; 
    bool pool = true;
    while (pool) {
        memset(read_buffer, '\0', sizeof(read_buffer));
        int read_buffer_size = sizeof(read_buffer) / sizeof(read_buffer[0]);
        if (read_buffer_size != READ_SIZE) READ_SIZE = read_buffer_size;
		printf("\nPolling for input... with max consume read buffer size from fd %d\n", read_buffer_size);
		event_count = epoll_wait(fd, events, MAX_EVENTS, 30000);
		printf("%d ready events\n", event_count);
		for (int i = 0; i < event_count; i++) {
			printf("Reading file descriptor '%d' -- ", events[i].data.fd);
			bytes_read = read(events[i].data.fd, read_buffer, read_buffer_size);
    		printf("%zd bytes read.\n", bytes_read);
            read_buffer[bytes_read] = '\0';
            for (int i=0; i <= strlen(read_buffer); i++) printf("%c", *(read_buffer + i));
			if(strncmp(read_buffer, "exit", 5)) break;
		}
	}

    if (close(fd)){
        perror("close");
        return 1; 
    }
    return 0;
}
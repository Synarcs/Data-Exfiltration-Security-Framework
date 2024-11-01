#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>

#include <linux/sched.h>

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define MAX_EVENTS 5 
#define READ_SIZE 10 

extern struct task_struct *  __fd_info(int fd);

int main(void) {
    struct  epoll_event event, events[MAX_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = 2;

    int fd = epoll_create1(0);

    int val = fcntl(fd, F_GETFL);
    int dup_val_fd = fcntl(fd, F_DUPFD);

    int sock_fd;
    if (sock_fd = socket(AF_INET, SOCK_DGRAM, 0 < 0)){
        perror("Error binding socket");
    }
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {}

    printf("File descriptor open information: %d\n", val);

    if (epoll_ctl(fd, EPOLL_CTL_ADD, 0, &event)) {
        perror("epoll_ctl");
        return 1;
    }

    pid_t proc = getpid();
    printf("Process ID adding epoll events over POLL STDIN: %d\n", proc); 
    int event_count = 0;
    size_t bytes_read;  char read_buffer[READ_SIZE + 1]; 
    bool pool = true;
    while (pool) {
		printf("\nPolling for input...\n");
        memset(read_buffer, '\0', sizeof(read_buffer));
		event_count = epoll_wait(fd, events, MAX_EVENTS, 30000);
		printf("%d ready events\n", event_count);
		for (int i = 0; i < event_count; i++) {
			printf("Reading file descriptor '%d' -- ", events[i].data.fd);
			bytes_read = read(events[i].data.fd, read_buffer, READ_SIZE);
    		printf("%zd bytes read.\n", bytes_read);
            read_buffer[bytes_read] = '\0';
            for (int i=0; i <= strlen(read_buffer); i++) printf("%c", *(read_buffer + i));
			if(strncmp(read_buffer, "exit\n", 5)) break;
		}
	}

    if (close(fd)){
        perror("close");
        return 1; 
    }
    return 0;
}
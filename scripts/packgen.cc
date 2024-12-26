#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint> 
#include <cstring> 
#include <vector>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <queue>
#include <signal.h>

typedef u_int32_t __u32; 

struct PacketGen {
    __u32 packet_class;
    __u32 protocol;
    void * GetHandler();
};

class PacketHandler {
    private:
        std::vector<__u32> watchpolledFd;
        struct PacketGen *packet; 
        const int capQueueSize = (int) 1e5;
    public:
        __u32 fd;
        std::queue<__u32> submissionWatchQueue;
        PacketHandler(int fd) { 
            this->fd = fd;
            this->packet = (struct PacketGen *) malloc(sizeof(struct PacketGen)); 
        }
        std::vector<__u32> GetWatchPolledFd();
        std::vector<__u32> GetWatchPolledFd(const int& size);
        bool submitTasksWatchQueue(__u32 * fd);
        ~PacketHandler() {
            free(this->packet);
        }
        __u32& GeneratePacket();
};

bool PacketHandler::submitTasksWatchQueue(__u32 * fd) {
    if ( this->submissionWatchQueue.size() == this->capQueueSize) return false;
    this->submissionWatchQueue.emplace(*fd);
    return true;
} 

std::vector<__u32> PacketHandler::GetWatchPolledFd() {
    return this->watchpolledFd;
} 

__u32& PacketHandler::GeneratePacket() { return fd; }

int main(void) {}

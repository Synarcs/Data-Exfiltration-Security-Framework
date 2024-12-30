#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint> 
#include <cstring> 
#include <vector>
#include <stdlib.h>
#include <memory>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <queue>
#include <signal.h>

typedef u_int32_t __u32; 

typedef struct PacketProcessHeader {
    __u32 packet_class;
    __u32 protocol;
    void * GetHandler();
} PacketProcessHeader __attribute__((packed));

class PacketHandler {
    private:
        std::vector<__u32> watchpolledFd;
        const int capQueueSize = (int) 1e5;
    protected:
        struct PacketProcessHeader *packet; 
    public:
        __u32 fd;
        std::queue<__u32> submissionWatchQueue;
        PacketHandler(PacketProcessHeader *header) { this->packet = header; }
        PacketHandler(int fd) { 
            this->fd = fd;
            this->packet = (struct PacketProcessHeader *) malloc(sizeof(PacketProcessHeader)); 
        }
        std::vector<__u32> GetWatchPolledFd();
        std::vector<__u32> GetWatchPolledFd(const int& size);
        bool submitTasksWatchQueue(__u32 * fd);
        ~PacketHandler() {
            std::cout << "Deallocate the allocated kernel memory " << std::endl;
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

int main(void) {
    PacketProcessHeader *header = new PacketProcessHeader();
    PacketHandler *handler = new PacketHandler(header);

    std::cout << "Page Size in memory is " << sysconf(_SC_PHYS_PAGES) << " " << sysconf(_SC_PAGESIZE) << " " << sysconf(_SC_THREAD_CPUTIME) << std::endl;
    std::cout << "size of the Packet Generator " << sizeof(handler) << std::endl;
    return 0;
}

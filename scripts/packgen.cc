#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <cstddef>
#include <vector>

#include <sys/ioctl.h>
#include <sys/socket.h>

using namespace std; 

typedef u_int32_t __u32; 

class PacketHandler {
    private:
        int fd;
        vector<__u32> watchpolledFd;
    public:
        PacketHandler(int fd) { this->fd = fd; }
        void * GeneratePacket();
};

void * PacketHandler::GeneratePacket() {
    return NULL;
}


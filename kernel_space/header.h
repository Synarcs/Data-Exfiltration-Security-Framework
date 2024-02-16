



struct __domain_event {
    char domain[255];
    char classification[1];
};

#ifndef DNS_PORT
    #define DNS_PORT = 53
#endif


#define MAX_SIZE = 1024;
#define MAX_ENTRIES = 1024;


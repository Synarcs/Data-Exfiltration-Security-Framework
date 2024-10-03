


#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))



#define __print_type(a, ...) __GENERIC(x, \ 
    __u8: bpf_printk("%u\n", a), \ 
    default: bpf_printk("Generic type not processed\n") \ 
)
#define __GENERIC_PRINT(x, ...) __GENERIC_TYPE(x, __VA_ARGS__) 




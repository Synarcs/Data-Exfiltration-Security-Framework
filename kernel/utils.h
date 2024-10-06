


#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define div(a, b) ((a) / (b))


#define forn_unroll(x,type , ...) _Pragma(unroll (x)) for (type i=0; i < x; i++)

#define fork_unroll(x, y , type, ...) _Pragma (unroll(x)) for (type i=x; i <= y; i++)


#define __print_type(a, ...) __GENERIC(x, \
    __u8: bpf_printk("%u\n", a) \
    default: bpf_printk("Generic type not processed\n") \
)

#define __GENERIC_PRINT(x, ...) __GENERIC_TYPE(x, __VA_ARGS__) 




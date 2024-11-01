


#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))



#define isUpper(a) ((a) - 'A' >= 0 && 'Z' - (a) >= 0)
#define isLower(a) ((a) - 'a' >= 0 && 'z' - (a) >= 0)
#define isDigit(a) ((a) - '0' >= 0 && '9' - (a) >= 0)



#define div(a, b) ((a) / (b))


#define forn_unroll(x,type , ...) _Pragma(unroll (x)) for (type i=0; i < x; i++)

#define fork_unroll(x, y , type, ...) _Pragma (unroll(x)) for (type i=x; i <= y; i++)


#define __print_type(a, ...) __GENERIC(x, \
    __u8: bpf_printk("%u\n", a) \
    default: bpf_printk("Generic type not processed\n") \
)

#define __GENERIC_PRINT(x, ...) __GENERIC_TYPE(x, __VA_ARGS__) 



#define CHECK_BOUNDS(ptr, offset, end, ct) \
    if ((void *)((ptr) + (offset) + 1) > (end)) \
        return (ct);

#define CHECK_BOUNDS_OFFSET(ptr, offset, end, ct)  \
    if ((void *)((ptr) + (offset)) > (end)) \
        return (ct);
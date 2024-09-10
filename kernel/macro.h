#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <unistd.h>
#include <stdint.h>

#define max(x, y) _Generic((x), \
    int: _MAX_NUM_INT, \
    double: _UNDEFINED_TYPES, \
    default: _UNDEFINED_TYPES, \
)(x, y);

#ifndef __DEBUG__
    #define __DEBUG__ true
#endif

#define _UNDEFINED_TYPES perror("Error the Required Type is not configured")
#define _MAX_NUM_INT(x,y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    (void) (&_x == &_y);        \
    _x < _y ? _x : _y; })
    
#define MASK(X) ((u_int64_t)1 << (X))
#define VAR_NAME(X, Y) X##Y
#define GENERIC_VAR_(TYPE, default) TYPE VAR_NAME(test_, default)

typedef uint64_t uSizemax_t;
typedef uint32_t uSizemid_t;


#define GENERIC_bpf_trace_printk(x, ...) _Generic((x), \
    uSizemax_t: bpf_trace_printk("\n \\\\\\ %lu", x), \
    u_int16_t: __DEBUG__  ? bpf_trace_printk("\n %lu", x) : NULL, \ 
    default: bpf_trace_printk("Unsupported type")); \
    bpf_trace_printk(__VA_ARGS__);

#define ForN(TYPE, val , ...) for (TYPE i=1; i <= val; i++) { GENERIC_bpf_trace_printk(i, __VA_ARGS__); bpf_trace_printk(__VA_ARGS__); }
#define ForNArr(TYPE,buf, ... ) for (TYPE i=0; i < sizeof(buf) / sizeof(buf[0]); i++) GENERIC_bpf_trace_printk(buf[i], __VA_ARGS__)

__attribute__((always_inline))
int test_runner(void *__restrict size_ptr) {
    double *cast = (double *)(size_ptr);
    if (*cast > (double) (1 << 4)) 
        bpf_trace_printk("A larget size memory found", *cast);
    return -1;
}

__attribute__((always_inline))
int test_print(int *__restrict size) { bpf_trace_printk("\n ////// the size is %d //// \n", *size); return 0; }

__attribute__((always_inline))
void * hoc(int (*test_func_ptr)(int *), int mxSize) {
    test_func_ptr(&mxSize);

    return NULL;
}

static const int SIZE = 100;

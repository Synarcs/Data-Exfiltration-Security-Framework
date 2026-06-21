#include <cstdint>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <sys/cdefs.h>
#include <unistd.h>
#include <stdint.h>

#define _UNDEFINED_TYPES perror("Error the Required Type is not configured")
#define _MAX_NUM_INT(x,y) ({ \
    typeof(x) _x = (x); \
    typeof(y) _y = (y); \
    (void) (&_x == &_y);        \
    _x < _y ? _x : _y; })
    
#define MASK(X) ((u_int64_t)1 << (X))
#define VAR_NAME(X, Y) X## Y
#define GENERIC_VAR_(TYPE, default) TYPE VAR_NAME(test_, default)

#define _MIN(x1, x2) ({  \ 
    typeof((x1)) _a = (x1); typeof(x2) _b = (x2);  \
    (_a) > (_b) ? (_a) : (_b);  \
})

typedef uint64_t uSizemax_t;
typedef uint32_t uSizemid_t;

#define BASE_DEBUG(...) do { \
            bpf_trace_printk(__VA_ARGS__); \
        } 

#define _bswap_generic(x) __Generic({   \
    uint32_t: __builtin_bswap32((x)),   \
    uint64_t: __builtin_bswap64((x)),   \
    default:  -1                        \
})

#define GENERIC_bpf_trace_printk(x, ...) _Generic((x), \
    uSizemax_t: bpf_trace_printk("\n \\\\\\ %lu", x), \
    u_int16_t: __DEBUG__  ? bpf_trace_printk("\n %lu", x) : NULL, \ 
    default:  BASE_DEBUG(__VA_ARGS);

#define ForN(TYPE, val , ...) for (TYPE i=1; i <= val; i++) { GENERIC_bpf_trace_printk(i, __VA_ARGS__); bpf_trace_printk(__VA_ARGS__); }
#define ForNArr(TYPE,buf, ... ) for (TYPE i=0; i < sizeof((buf)) / sizeof((buf[0])); i++) GENERIC_bpf_trace_printk(buf[i], __VA_ARGS__)

static __always_inline
int test_print(int *__restrict size) { bpf_trace_printk("\n ////// the size is %d //// \n", *size); return 0; }

static __always_inline
void * hoc(int (*test_func_ptr)(int *), int mxSize) {
    test_func_ptr(&mxSize);
    return NULL;
}

static
__always_inline int allocate() {
    return _MIN(2, 3);
}
static const int SIZE = 100;

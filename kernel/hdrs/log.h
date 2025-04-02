#ifndef MATH_H
#define MATH_H

#include <linux/bpf.h>

#define MAX_DNS_SERVICE_CHAR_LIMIT 255
#define NEWTON_RAPHSON_ITERATIONS 20

static 
__always_inline __u32 __approx_log(__u8 xx) {
    __u8 ans = 0;
    __u8 temp = xx;
    if (xx > MAX_DNS_SERVICE_CHAR_LIMIT) xx = MAX_DNS_SERVICE_CHAR_LIMIT;
    while (xx > 1) {
        ans++;
        xx >>= 1;
    }

    __u32 frac = 0;
    temp = xx;

    // Newton-Raphson iteration for iterative log estimation 
    for (int i = 0; i < NEWTON_RAPHSON_ITERATIONS; i++) { 
        temp = (temp * temp) / ((1 << ans) * 2); // 
        frac |= (temp >= 1000) ? (1 << (9 - i)) : 0;
    }

    return (__u32) ((ans * 1000) + frac);
}


#endif MATH_H 
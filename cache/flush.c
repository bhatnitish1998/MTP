#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cpuid.h>
#include <x86intrin.h>

void flush_llc() {
    unsigned int eax, ebx, ecx, edx;
    unsigned int cache_line_size;

    // Get the cache line size
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        cache_line_size = (ebx & 0xFF00) >> 5; // bits 15-8
    } else {
        fprintf(stderr, "Failed to get cache line size\n");
        return;
    }

    // Create a buffer large enough to fill the LLC
    size_t buffer_size = 60 * 1024 * 1024; // 60 MB
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        perror("malloc failed");
        return;
    }

    // Access each cache line to flush the LLC
    for (size_t i = 0; i < buffer_size; i += cache_line_size) {
        _mm_clflush(&buffer[i]);
    }

    free(buffer);
}

int main() {
    flush_llc();
    return 0;
}

#ifndef _UNICORNSIMPLEHEAP
#define _UNICORNSIMPLEHEAP

#include <unicorn/unicorn.h>
#include <iostream>
#include <functional>
#include <algorithm>
#include <vector>
#include <cstdlib>

#define UNICORN_PAGE_SIZE 0x1000

#define DEBUG(fmt,...) do { \
  if (debug_trace) { printf(fmt, ##__VA_ARGS__); putchar('\n'); } \
} while (0)

#define uc_assert_err(expect, err)                                  \
do {                                                                \
    uc_err __err = err;                                             \
    if (__err != expect) {                                          \
        fprintf(stderr, "%s", uc_strerror(__err));                  \
        exit(1);                                                    \
    }                                                               \
} while (0)

#define uc_assert_success(err)  uc_assert_err(UC_ERR_OK, err)

inline uint32_t CHUNK(const uint32_t& x) { return x - (x & 0xfff); }
inline uint32_t CHUNK_DATA(const uint32_t& addr, const uint32_t& size) { return addr + (UNICORN_PAGE_SIZE - (size & 0xfff)); }
inline uint32_t CHUNK_DATA_SIZE(const uint32_t& addr, const uint32_t& size) { return size - ((addr&0xfff) + UNICORN_PAGE_SIZE); }

inline uint64_t ALIGN_PAGE_DOWN(const uint64_t& x) { return x & ~(UNICORN_PAGE_SIZE - 1); }
inline uint64_t ALIGN_PAGE_UP(const uint64_t& x) { return (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1); }

struct HeapChunk{
    uint32_t addr;
    uint32_t size;
};

bool Compare_Chunk(const HeapChunk& rhs, const uint32_t& addr);

class UnicornSimpleHeap{
private:
    uc_engine *uc;
    bool debug_trace;
    std::vector<HeapChunk> chunks;
        
    enum{
        HEAP_MIN_ADDR = 0x40002000,
        HEAP_MAX_ADDR = 0xFFFFFFFF
    };
public:
    UnicornSimpleHeap(uc_engine* _uc, bool _debug_trace);
    uint32_t malloc(uint32_t size);
    uint32_t calloc(uint32_t size, uint32_t count);
    uint32_t realloc(uint32_t addr, uint32_t size);
    uint32_t free(uint32_t addr);
};

#endif
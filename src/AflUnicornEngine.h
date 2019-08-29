#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <unicorn/unicorn.h>
#include <zlib.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdint>
#include <csignal>

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

extern void _error(const char* err_msg);

using json = nlohmann::json;

typedef std::map<std::string, int> Regmap;

#pragma pack(push, 1)
struct SegmentDescriptor {
   union {
      struct {   
#if __BYTE_ORDER == __LITTLE_ENDIAN
         unsigned short limit0;
         unsigned short base0;
         unsigned char base1;
         unsigned char type:4;
         unsigned char system:1;      /* S flag */
         unsigned char dpl:2;
         unsigned char present:1;     /* P flag */
         unsigned char limit1:4;
         unsigned char avail:1;
         unsigned char is_64_code:1;  /* L flag */
         unsigned char db:1;          /* DB flag */
         unsigned char granularity:1; /* G flag */
         unsigned char base2;
#else
         unsigned char base2;
         unsigned char granularity:1; /* G flag */
         unsigned char db:1;          /* DB flag */
         unsigned char is_64_code:1;  /* L flag */
         unsigned char avail:1;
         unsigned char limit1:4;
         unsigned char present:1;     /* P flag */
         unsigned char dpl:2;
         unsigned char system:1;      /* S flag */
         unsigned char type:4;
         unsigned char base1;
         unsigned short base0;
         unsigned short limit0;
#endif
      };
      uint64_t desc;
   };
};
#pragma pack(pop)

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code);

struct uc_settings{
    uc_arch arch;
    uc_mode mode;
};

class AflUnicornEngine{
private:
    uc_engine *uc;
    uc_settings uc_set;
    bool debug_trace;
    
public:
    AflUnicornEngine(const std::string context_dir, bool enable_trace=false, bool _debug_trace=false);
    void _map_segments(const json& segment_list, const std::string context_dir);
    void _map_segment(const std::string name, const uint64_t address, const uint64_t size, int perms);
    void mapGDT(const uint32_t fs_addr);
    void dump_regs() const;
    void force_crash(uc_err err) const;
    uc_settings _get_arch_and_mode(const std::string arch_str) const;
    Regmap _get_register_map(uc_mode mode) const;
    
    uc_engine* get_uc() const;
};

#endif
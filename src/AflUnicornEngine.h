#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE

#include <iostream>
#include <fstream>
#include <string>
#include <unicorn/unicorn.h>
#include <zlib.h>
#include <nlohmann/json.hpp>
#include <map>
#include <cstdint>
#include <cstdio>

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

#define X86 0

extern void _error(const char* err_msg);

using json = nlohmann::json;

class AflUnicornEngine{
private:
    uc_engine *uc;
    bool debug_trace;
    
public:
    AflUnicornEngine(const std::string context_dir, bool enable_trace=false, bool _debug_trace=false);
    void _map_segments(const json& segment_list, const std::string context_dir);
    void _map_segment(const std::string name, const uint64_t address, const uint64_t size, int perms);
    void dump_regs() const;
    std::map<std::string, int> _get_register_map(int arch) const;
};

#endif
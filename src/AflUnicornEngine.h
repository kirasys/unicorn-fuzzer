#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE


#include <iostream>
#include <fstream>
#include <string>
#include <unicorn/unicorn.h>
#include <nlohmann/json.hpp>
#include <map>
#include <cstdint>
#include <cstdio>

#define DEBUG(fmt,...) do { \
  if (debug_trace) { printf(fmt, ##__VA_ARGS__); putchar('\n'); } \
} while (0)

#define X86 0

using json = nlohmann::json;

class AflUnicornEngine{
private:
    uc_engine *uc;
    bool debug_trace;
    
public:
    AflUnicornEngine(const char* context_dir, bool enable_trace=false, bool debug_trace=false);
    void _map_segments(const json& segment_list, const char* context_dir);
    void _map_segment(const std::string name, const uint64_t address, const uint64_t size, int perms);
    std::map<std::string, int> _get_register_map(int arch);
};

#endif
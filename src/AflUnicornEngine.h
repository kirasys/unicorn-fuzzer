#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE


#include <iostream>
#include <fstream>
#include <string>
#include <unicorn/unicorn.h>
#include <nlohmann/json.hpp>
#include <map>
#include <cstdint>

#define DEBUG(x) do { \
  if (debug_trace) { std::cerr << x << std::endl; } \
} while (0)

#define X86 0

using json = nlohmann::json;

class AflUnicornEngine{
private:
    uc_engine *uc;
    
public:
    AflUnicornEngine(const char* context_dir, bool enable_trace=false, bool debug_trace=false);
    void _map_segments(const json& segment_list, const char* context_dir);
    std::map<std::string, int> _get_register_map(int arch);
};

#endif
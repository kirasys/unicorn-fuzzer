#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE


#include <iostream>
#include <fstream>
#include <string>
#include <unicorn/unicorn.h>
#include <json/value.h>
#include <jsoncpp/json/json.h>

#define DEBUG(x) do { \
  if (debug_trace) { std::cerr << x << std::endl; } \
} while (0)

class AflUnicornEngine{
private:
    uc_engine *uc;
    
public:
    AflUnicornEngine(const char* context_dir, bool enable_trace=false, bool debug_trace=false);
};

#endif
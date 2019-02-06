#ifndef _AFLUNICORNENGINE
#define _AFLUNICORNENGINE


#include <iostream>
#include <fstream>
#include <string>
#include <unicorn/unicorn.h>
#include <json/value.h>
#include <jsoncpp/json/json.h>
#include <map>

#define DEBUG(x) do { \
  if (debug_trace) { std::cerr << x << std::endl; } \
} while (0)

#define X86 0

class AflUnicornEngine{
private:
    uc_engine *uc;
    
public:
    AflUnicornEngine(const char* context_dir, bool enable_trace=false, bool debug_trace=false);
    std::map<char*, int> _get_register_map(int arch){
        std::map<char*, int> r_map;
        if(arch == X86){
            r_map["eax"] = UC_X86_REG_EAX;
            r_map["ebx"] = UC_X86_REG_EBX;
            r_map["ecx"] = UC_X86_REG_ECX;
            r_map["edx"] = UC_X86_REG_EDX;
            r_map["esi"] = UC_X86_REG_ESI;
            r_map["edi"] = UC_X86_REG_EDI;
            r_map["ebp"] = UC_X86_REG_EBP;
            r_map["esp"] = UC_X86_REG_ESP;
            r_map["eip"] = UC_X86_REG_EIP;
            r_map["efl"] = UC_X86_REG_EFLAGS;
            // Segment registers are removed
            // Set a segment registers in another function
        }
        
        return r_map;
    }
};

#endif
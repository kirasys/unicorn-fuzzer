#include "AflUnicornEngine.h"

const char* INDEX_FILE_NAME = "_index.json";

AflUnicornEngine::AflUnicornEngine(const char* context_dir, bool enable_trace, bool debug_trace){
    DEBUG("Loading process context");
        
    // Making full path of index file
    std::string index_dir(context_dir);
    index_dir.append("/");
    index_dir.append(INDEX_FILE_NAME);
        
    // Read _index.json file
    Json::Value context;
    std::ifstream index_file(index_dir.c_str());
    index_file >> context;
        
    if(context["arch"] == 0 || context["regs"] == 0 || \
         context["segments"] == 0){
        std::cerr << "Couldn't find infomation in indexfile" << std::endl;
        return;
    }
        
    // Only support ARCH_86 & MODE_32 now
    uc_open(UC_ARCH_X86, UC_MODE_32, &this->uc);
    
    // Load the registers
    std::map<char*, int> reg_map = AflUnicornEngine::_get_register_map(X86);
    
    for(auto &reg: reg_map){
        uc_reg_write(this->uc, reg.second, &context["regs"][reg.first]);
        std::cout<<reg.first<<' '<<reg.second<<'\n';
    }
    
}

std::map<char*, int> AflUnicornEngine::_get_register_map(int arch){
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
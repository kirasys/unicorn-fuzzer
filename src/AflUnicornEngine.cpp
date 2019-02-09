#include "AflUnicornEngine.h"

const char* INDEX_FILE_NAME = "_index.json";

AflUnicornEngine::AflUnicornEngine(const char* context_dir, bool enable_trace, bool debug_trace){
    DEBUG("Loading process context");
        
    // Making full path of index file
    std::string index_dir(context_dir);
    index_dir.append("/");
    index_dir.append(INDEX_FILE_NAME);
        
    // Read _index.json file
    json context;
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
    std::map<std::string, int> reg_map = AflUnicornEngine::_get_register_map(X86);
    
    for(auto &reg: reg_map)
        uc_reg_write(this->uc, reg.second, &context["regs"][reg.first]);
        
    // Map the memory segment and load data
    AflUnicornEngine::_map_segments(context["segments"], context_dir);
}

void AflUnicornEngine::_map_segments(const json& segment_list, const char* context_dir){
    for(auto &segment: segment_list){
        std::string name = segment["name"].get<std::string>();
        int64_t start = segment["start"].get<int64_t>();
        int64_t end = segment["end"].get<int64_t>();
        
        int perms = (segment["permissions"]["r"] == true? UC_PROT_READ: 0) | \
                    (segment["permissions"]["w"] == true? UC_PROT_WRITE: 0) | \
                    (segment["permissions"]["x"] == true? UC_PROT_EXEC: 0);
    }
}

std::map<std::string, int> AflUnicornEngine::_get_register_map(int arch){
        std::map<std::string, int> r_map;
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
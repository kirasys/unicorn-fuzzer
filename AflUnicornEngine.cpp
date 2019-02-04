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
    uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
        
    std::cout << context["regs"];
        
}
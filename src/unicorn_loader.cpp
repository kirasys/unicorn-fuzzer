#include <unicorn/unicorn.h>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include "AflUnicornEngine.h"

int main(int argc, char* argv[]){
    if(argc < 4){
        std::cerr << "Usage : ./unicorn_loader CONTEXT_DIR ENABLE_TRACE(true|false) DEBUG_TRACE(true|false)" << std::endl;
        return 0;
    }
    const std::string context_dir = argv[1];
    bool enable_trace = strcmp(argv[2], "true")? false : true;
    bool debug_trace = strcmp(argv[3], "true")? false : true;
    
    AflUnicornEngine afl = AflUnicornEngine(context_dir, enable_trace, debug_trace);
    
    
}
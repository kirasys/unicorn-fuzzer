#include <unicorn/unicorn.h>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include "AflUnicornEngine.h"
#include "UnicornSimpleHeap.h"

const uint64_t start_address = 0x8048420;
const uint64_t end_address = 0x08048442;
const uint64_t _printf = 0x80482f0;

static void unicorn_hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    if(address == _printf){ // printf
        uint32_t esp;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        
        uint32_t ret_addr;
        uc_mem_read(uc, esp, &ret_addr, sizeof(ret_addr));
        uc_reg_write(uc, UC_X86_REG_EIP, &ret_addr);
        
        esp += 4;
        uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    }
}

int main(int argc, char* argv[]){
    if(argc < 4){
        std::cerr << "Usage : ./unicorn_loader CONTEXT_DIR ENABLE_TRACE(true|false) DEBUG_TRACE(true|false)" << std::endl;
        return 0;
    }
    const std::string context_dir = argv[1];
    bool enable_trace = strcmp(argv[2], "true")? false : true;
    bool debug_trace = strcmp(argv[3], "true")? false : true;
    
    AflUnicornEngine afl = AflUnicornEngine(context_dir, enable_trace, debug_trace);
    UnicornSimpleHeap uc_heap = UnicornSimpleHeap(afl.get_uc(), true);
    
    uc_hook trace;
    uc_hook_add(afl.get_uc(), &trace, UC_HOOK_CODE, reinterpret_cast<void*>(unicorn_hook_instruction), NULL, 1, 0);
    
    uint32_t eip = start_address;
    while(eip != end_address){
        uc_err err = uc_emu_start(afl.get_uc(), eip, 0xffffffff, 0, 0);
        if(err){
            fprintf(stderr, "%s", uc_strerror(err));
            afl.dump_regs();
            return 0;
        }
        uc_reg_read(afl.get_uc(), UC_X86_REG_EIP, &eip);
    }
    
    afl.dump_regs();
}
#include "UnicornSimpleHeap.h"

UnicornSimpleHeap::UnicornSimpleHeap(uc_engine* _uc, bool _debug_trace) 
        : uc(_uc), debug_trace(_debug_trace) {}

uint32_t UnicornSimpleHeap::malloc(uint32_t size){
        // Figure out the overall size to be allocated/mapped
        //    - Allocate at least 1 4k page of memory to make Unicorn happy
        //    - Add guard pages at the start and end of the region
    uint32_t total_chunk_size = UNICORN_PAGE_SIZE + ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE;
    
    HeapChunk chunk = {0,0};
    for(uint32_t addr = HEAP_MIN_ADDR; addr < HEAP_MAX_ADDR; addr += UNICORN_PAGE_SIZE){
        uc_err err = uc_mem_map(this->uc, addr, total_chunk_size, UC_PROT_WRITE | UC_PROT_WRITE);

        if(err == UC_ERR_OK){
            chunk.addr = addr;
            chunk.size = total_chunk_size;
            DEBUG("Allocating 0x%x-byte chunk @ 0x%x", size, addr + UNICORN_PAGE_SIZE);
            break;
        }
    }
    // Something went wrong.
    if(!chunk.addr) return 0;
    
    this->chunks.push_back(chunk);
    return chunk.addr + UNICORN_PAGE_SIZE;
}
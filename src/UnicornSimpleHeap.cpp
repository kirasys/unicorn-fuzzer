#include "UnicornSimpleHeap.h"

UnicornSimpleHeap::UnicornSimpleHeap(uc_engine* _uc, bool _debug_trace) 
        : uc(_uc), debug_trace(_debug_trace) {}

uint32_t UnicornSimpleHeap::malloc(uint32_t size){
    // Figure out the overall size to be allocated/mapped
    //    - Allocate at least 1 4k page of memory to make Unicorn happy
    //    - Add guard page at the end of the region
    uint32_t total_chunk_size = ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE;
    
    // Very simple Allocating algorithm..
    HeapChunk chunk = {0,0};
    for(uint32_t addr = HEAP_MIN_ADDR; addr < HEAP_MAX_ADDR; addr += UNICORN_PAGE_SIZE){
        uc_err err = uc_mem_map(this->uc, addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE);

        if(err == UC_ERR_OK){
            chunk.addr = addr;
            chunk.size = total_chunk_size;
            break;
        }
    }
    // Something went wrong.
    if(!chunk.addr) return 0;
    
    // Chunk size will be used in the free function.
    uc_err err = uc_mem_write(this->uc, chunk.addr-4, &total_chunk_size, sizeof(total_chunk_size));
    uc_assert_success(err);
    
    // Change the guard page permission to readonly.
    err = uc_mem_protect(this->uc, chunk.addr + chunk.size - UNICORN_PAGE_SIZE, UNICORN_PAGE_SIZE, UC_PROT_READ);
    uc_assert_success(err);
    
    this->chunks.push_back(chunk);
    
    uint32_t data_addr = chunk.addr + (UNICORN_PAGE_SIZE - (size & 0xfff));
    DEBUG("Allocating 0x%x byte chunk @ 0x%x", size, data_addr);
    
    return data_addr;
}


bool UnicornSimpleHeap::free(uint32_t addr){
    uint32_t chunksize;
    
    uc_err err = uc_mem_read(this->uc, addr-4, &chunksize, sizeof(chunksize));
    uc_assert_success(err);
    
    return true;
}
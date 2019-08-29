#include "UnicornSimpleHeap.h"

bool Compare_Chunk(const HeapChunk& rhs, const uint32_t& addr){
    return addr == rhs.addr;
}

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
    
    // Change the guard page permission to readonly.
    uc_err err = uc_mem_protect(this->uc, chunk.addr + chunk.size - UNICORN_PAGE_SIZE, UNICORN_PAGE_SIZE, UC_PROT_READ);
    uc_assert_success(err);

    // Put a chunk
    this->chunks.push_back(chunk);
    
    uint32_t data_addr = CHUNK_DATA(chunk.addr, size);
    DEBUG("Allocating 0x%x byte chunk @ 0x%x", size, data_addr);
    
    return data_addr;
}

uint32_t UnicornSimpleHeap::calloc(uint32_t size, uint32_t count){
    return UnicornSimpleHeap::malloc(size * count);
}

uint32_t UnicornSimpleHeap::realloc(uint32_t addr, uint32_t size){
    DEBUG("Reallocating chunk @ 0x%x to be 0x%x bytes", addr, size);
    
    std::vector<HeapChunk>::iterator chunk_itr = std::find_if(chunks.begin(), chunks.end(), \
                                                   std::bind(Compare_Chunk, std::placeholders::_1, CHUNK(addr)));
    
    // Something went wrong. (memory corruption?)
    if(chunk_itr == chunks.end())
        return 0;
    
    if(size == 0)
        return UnicornSimpleHeap::free(addr);
    
    // Read original data.
    void* ori_data = std::malloc(CHUNK_DATA_SIZE(addr, chunk_itr->size));
    uc_err err = uc_mem_read(this->uc, addr, ori_data, CHUNK_DATA_SIZE(addr, chunk_itr->size));
    uc_assert_success(err);
    
    // Write the data to new chunk.
    uint32_t new_chunk = UnicornSimpleHeap::malloc(size);
    err = uc_mem_write(this->uc, static_cast<uint64_t>(new_chunk), ori_data, \
                              CHUNK_DATA_SIZE(addr, chunk_itr->size));
    uc_assert_success(err);
    
    // Free old chunk
    std::free(ori_data);
    if(UnicornSimpleHeap::free(addr))
        return 0;
    
    return new_chunk;
}

uint32_t UnicornSimpleHeap::free(uint32_t addr){
    std::vector<HeapChunk>::iterator chunk_itr = std::find_if(chunks.begin(), chunks.end(), \
                                                   std::bind(Compare_Chunk, std::placeholders::_1, CHUNK(addr)));
    
    // Something went wrong. (double free or memory corruption?)
    if(chunk_itr == chunks.end())
        return -1;
    
    DEBUG("Freeing 0x%x byte chunk @ 0x%x", chunk_itr->size, addr);
    uc_err err = uc_mem_unmap(this->uc, CHUNK(addr), chunk_itr->size);
    uc_assert_success(err);
    
    // Remove a chunk
    chunks.erase(chunk_itr);
    
    return 0;
}
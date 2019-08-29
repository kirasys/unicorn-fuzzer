#include "AflUnicornEngine.h"

const char* INDEX_FILE_NAME = "_index.json";
const uint64_t MAX_ALLOWABLE_SEG_SIZE = 1024*1024*1024;
const uint64_t UNICORN_PAGE_SIZE = 0x1000;

inline uint64_t ALIGN_PAGE_DOWN(uint64_t x) { return x & ~(UNICORN_PAGE_SIZE - 1); }
inline uint64_t ALIGN_PAGE_UP(uint64_t x) { return (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1); }

void _error(const char* err_msg){
    std::cerr << err_msg;
    exit(-1);
}

AflUnicornEngine::AflUnicornEngine(const std::string context_dir, bool enable_trace, bool _debug_trace) // enable_trace mode not surpported now.
    : debug_trace(_debug_trace){
    // Making full path of index file
    std::string index_dir = context_dir + "/" + INDEX_FILE_NAME;
    DEBUG("Loading process context index from %s", index_dir.c_str());
    
    // Read _index.json file
    json context;
    std::ifstream index_file(index_dir.c_str());
    index_file >> context;
    
    if(context["arch"] == 0 || context["regs"] == 0 || \
         context["segments"] == 0)
        _error("Couldn't find infomation in indexfile.");
    
    uc_err err;
    
    // Only support ARCH_86 & MODE_32 now
    this->uc_set = _get_arch_and_mode(context["arch"]["arch"]);
    err = uc_open(uc_set.arch, uc_set.mode, &this->uc);
    uc_assert_success(err);
    
    // Load the registers
    Regmap reg_map = AflUnicornEngine::_get_register_map(uc_set.mode);
    
    for(auto &reg: reg_map){
        uint64_t reg_value = context["regs"][reg.first].get<uint64_t>();
        
        err = uc_reg_write(this->uc, reg.second, &reg_value);
        uc_assert_success(err);   
    }
    
    // Map the memory segment and load data
    AflUnicornEngine::_map_segments(context["segments"], context_dir);
    DEBUG("Done context loading.");
}

void AflUnicornEngine::_map_segment(const std::string name, const uint64_t address, const uint64_t size, int perms){
    uint64_t mem_start_aligned = ALIGN_PAGE_DOWN(address);
    uint64_t mem_end_aligned = ALIGN_PAGE_UP(address + size);
    
    DEBUG("Mapping segment from %lx - %lx with perm=%d :%s",\
          mem_start_aligned, mem_end_aligned, perms, name.c_str());
    
    if(mem_start_aligned < mem_end_aligned){
        uc_err err = uc_mem_map(this->uc, mem_start_aligned, mem_end_aligned - mem_start_aligned, perms);
        uc_assert_success(err);
    }
}

void AflUnicornEngine::_map_segments(const json& segment_list, const std::string context_dir){
    for(const auto &segment: segment_list){
        std::string seg_name = segment["name"].get<std::string>();
        uint64_t seg_start = segment["start"].get<uint64_t>();
        uint64_t seg_end = segment["end"].get<uint64_t>();
        
        int seg_perms = (segment["permissions"]["r"].get<bool>() == true? UC_PROT_READ: 0) | \
                    (segment["permissions"]["w"].get<bool>() == true? UC_PROT_WRITE: 0) | \
                    (segment["permissions"]["x"].get<bool>() == true? UC_PROT_EXEC: 0);
        
        // Check if segment is of an acceptable size.
        if(seg_end - seg_start > MAX_ALLOWABLE_SEG_SIZE){
            DEBUG("Skipping segment (larger than %lu) : %s", MAX_ALLOWABLE_SEG_SIZE, seg_name.c_str());
            continue;
        }
        
        // Check for any overlap with existing segments. If there is, it must
        // be consolidated and merged together before mapping since Unicorn
        // doesn't allow overlapping segments.

        uint32_t count;
        uc_mem_region *regions;
        uc_mem_regions(this->uc, &regions, &count);

        bool pass = false;
        bool overlap_start = false;
        bool overlap_end = false;
        uint64_t tmp = 0;
        
        for(uint32_t i=0; i<count; i++){
            uint64_t mem_start = regions[i].begin;
            uint64_t mem_end = regions[i].end + 1;
            
            if(seg_start >= mem_start && seg_end < mem_end){
                pass = true;
                break;
            }
            if(seg_start >= mem_start && seg_start < mem_end){
                overlap_start = true;
                tmp = mem_end;
                break;
            }
            if(seg_end >= mem_start && seg_end < mem_end){
                overlap_end = true;
                tmp = mem_start;
                break;
            }
        }
        
        uc_free(regions);
        
        // Map memory into the address space
        if(!pass){
            if(overlap_start)             // Partial overlap (start)
                AflUnicornEngine::_map_segment(seg_name, tmp, seg_end - tmp, seg_perms);
            else if(overlap_end)          // Partial overlap (end)
                AflUnicornEngine::_map_segment(seg_name, seg_start, tmp - seg_start, seg_perms);
            else                          // Not found
                AflUnicornEngine::_map_segment(seg_name, seg_start, seg_end - seg_start, seg_perms);
        }
        else
            DEBUG("Segment %s already mapped. Moving on.", seg_name.c_str());
        
        // Load the content (if available)
        if(segment["content_file"].get<std::string>().length() > 0){
            std::string content_file_path = context_dir + "/" + segment["content_file"].get<std::string>();
            
            std::ifstream context_file(content_file_path.c_str(), std::ios::binary);
            if(!context_file)
                _error("Couldn't find context file. (Missing in context dir)");
            
            uLong content_size = seg_end - seg_start;
            Bytef* dcompr = new Bytef[content_size];
            std::vector<Bytef> compr(std::istreambuf_iterator<char>(context_file), {}); // Read all compressed data into buffer.
            
            int zerr = uncompress(dcompr, &content_size, reinterpret_cast<Bytef*>(compr.data()), compr.size());
            assert(zerr == Z_OK);
            
            uc_err err = uc_mem_write(this->uc, seg_start, dcompr, content_size);
            uc_assert_success(err);
            
            delete []dcompr;
        }
    }
}

//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0;  //clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff) {
        //need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;

    //some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1;   //32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1;  //code or data
}

void AflUnicornEngine::mapGDT(const uint32_t fs_address){
    uc_err err;
    uc_x86_mmr gdtr;
    
    const uint64_t gdt_address = 0xc0000000;

    struct SegmentDescriptor *gdt = (struct SegmentDescriptor*)calloc(31, sizeof(struct SegmentDescriptor));

    int r_cs = 0x73;
    int r_ss = 0x88;      //ring 0
    int r_ds = 0x7b;
    int r_es = 0x7b;
    int r_fs = 0x83;

    gdtr.base = gdt_address;  
    gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

    init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
    init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
    init_descriptor(&gdt[16], fs_address, 0xfff, 0);  //one page data segment simulate fs
    init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
    gdt[17].dpl = 0;  //set descriptor privilege level
    

    // map 64k for a GDT
    err = uc_mem_map(uc, gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
    uc_assert_success(err);

    //set up a GDT BEFORE you manipulate any segment registers
    err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
    uc_assert_success(err);

    // write gdt to be emulated to memory
    err = uc_mem_write(uc, gdt_address, gdt, 31 * sizeof(struct SegmentDescriptor));
    uc_assert_success(err);

    // when setting SS, need rpl == cpl && dpl == cpl
    // emulator starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
    err = uc_reg_write(uc, UC_X86_REG_SS, &r_ss);
    uc_assert_success(err);

    err = uc_reg_write(uc, UC_X86_REG_CS, &r_cs);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_DS, &r_ds);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_ES, &r_es);
    uc_assert_success(err);
    err = uc_reg_write(uc, UC_X86_REG_FS, &r_fs);
    uc_assert_success(err);
    
    DEBUG("Done segments register loading.");
}

void AflUnicornEngine::dump_regs() const {
    Regmap reg_map = AflUnicornEngine::_get_register_map(this->uc_set.mode);
    
    for(const auto &reg: reg_map){
        uint64_t reg_value;
        uc_err err = uc_reg_read(this->uc, reg.second, &reg_value);
        uc_assert_success(err);
        
        uc_mode mode = this->uc_set.mode;
        switch(mode){
            case UC_MODE_32:
                printf(">>> %s : %x \n",reg.first.c_str(), static_cast<uint32_t>(reg_value));
                break;
            case UC_MODE_64:
                printf(">>> %s : %lx \n",reg.first.c_str(), static_cast<uint64_t>(reg_value));
                break;
        }
    }
}

uc_settings AflUnicornEngine::_get_arch_and_mode(const std::string arch_str) const{
    static std::map<std::string, uc_settings> arch_map = {{"x86", {UC_ARCH_X86, UC_MODE_32}}};
    
    return arch_map[arch_str];
}

std::map<std::string, int> AflUnicornEngine::_get_register_map(uc_mode mode) const{
    Regmap r_map;
    if(mode == UC_MODE_32){
        r_map["eax"] = UC_X86_REG_EAX;
        r_map["ebx"] = UC_X86_REG_EBX;
        r_map["ecx"] = UC_X86_REG_ECX;
        r_map["edx"] = UC_X86_REG_EDX;
        r_map["esi"] = UC_X86_REG_ESI;
        r_map["edi"] = UC_X86_REG_EDI;
        r_map["ebp"] = UC_X86_REG_EBP;
        r_map["esp"] = UC_X86_REG_ESP;
        r_map["eip"] = UC_X86_REG_EIP;
        r_map["eflags"] = UC_X86_REG_EFLAGS;
        // Segment registers are removed
        // Set a segment registers in another function
    }
        
    return r_map;
}

void AflUnicornEngine::force_crash(uc_err err) const{
    static std::vector<uc_err> mem_errors = {UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED, \
                                         UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED, \
                                         UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED};
    
    if(std::find(mem_errors.begin(), mem_errors.end(), err) != mem_errors.end())
        std::raise(SIGSEGV);
    else if(err == UC_ERR_INSN_INVALID)
        std::raise(SIGILL);
    else
        std::raise(SIGABRT);
}

uc_engine* AflUnicornEngine::get_uc() const{
    return this->uc;
}

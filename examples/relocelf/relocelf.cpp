
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <elfio/elfio.hpp>
#include <unordered_map>

using namespace ELFIO;

using FuncMap = std::unordered_map<std::string, std::string>;

#define DUMP_DEC_FORMAT( width ) \
    std::setw( width ) << std::setfill( ' ' ) << std::dec << std::right
#define DUMP_HEX0x_FORMAT( width ) \
    "0x" << std::setw( width ) << std::setfill( '0' ) << std::hex << std::right
#define DUMP_HEX_FORMAT( width ) \
    std::setw( width ) << std::setfill( '0' ) << std::hex << std::right
#define DUMP_STR_FORMAT( width ) \
    std::setw( width ) << std::setfill( ' ' ) << std::hex << std::left

FuncMap GetFuncMap(const std::string &functext)
{
    FuncMap map;
    std::ifstream infile;
    infile.open(functext, std::ios::in);
    if (!infile.is_open()) {
        std::cout << "open file : " <<  functext << " failed! \n";
        return map;
    }
    std::string func;
    while(std::getline(infile, func)) {
        std::cout << func << std::endl;
        (void)map.emplace(func, func);
    }
    return map;
}

static const struct symbol_bind_t
{
    const Elf_Word key;
    const char*    str;
} symbol_bind_table[] = {
    { STB_LOCAL, "LOCAL" },   { STB_GLOBAL, "GLOBAL" },
    { STB_WEAK, "WEAK" },     { STB_LOOS, "LOOS" },
    { STB_HIOS, "HIOS" },     { STB_MULTIDEF, "MULTIDEF" },
    { STB_LOPROC, "LOPROC" }, { STB_HIPROC, "HIPROC" },
};

static const struct symbol_type_t
{
    const Elf_Word key;
    const char*    str;
} symbol_type_table[] = {
    { STT_NOTYPE, "NOTYPE" }, { STT_OBJECT, "OBJECT" },
    { STT_FUNC, "FUNC" },     { STT_SECTION, "SECTION" },
    { STT_FILE, "FILE" },     { STT_COMMON, "COMMON" },
    { STT_TLS, "TLS" },       { STT_LOOS, "LOOS" },
    { STT_HIOS, "HIOS" },     { STT_LOPROC, "LOPROC" },
    { STT_HIPROC, "HIPROC" },
};

static const struct symbol_vis_t
{
    const Elf_Word key;
    const char*    str;
} symbol_vis_table[] = {
    { STV_DEFAULT, "DEFAULT" }, { STV_INTERNAL, "INTERNAL" },
    { STV_HIDDEN, "HIDDEN" },     { STV_PROTECTED, "PROTECTED" },
};


template <typename T, typename K>
std::string static find_value_in_table( const T& table, const K& key )
{
    std::string res = "?";
    for (unsigned int i = 0; i < sizeof( table ) / sizeof( table[0] ); ++i ) {
        if ( table[i].key == key ) {
            res = table[i].str;
            break;
        }
    }

    return res;
}

std::string str_symbol_type(unsigned char type)
{
    return find_value_in_table(symbol_type_table, type);
}
std::string str_symbol_bind(unsigned char bind)
{
    return find_value_in_table(symbol_bind_table, bind);
}
std::string str_symbol_vis(unsigned char other)
{
    return find_value_in_table(symbol_vis_table, other);
}


void show_symbol(   Elf_Xword          no,
                    const std::string& name,
                    Elf64_Addr         value,
                    Elf_Xword          size,
                    unsigned char      bind,
                    unsigned char      type,
                    Elf_Half           shndx,
                    unsigned char      other
                    )
{
    std::ios_base::fmtflags original_flags = std::cout.flags();
    
    std::cout << "[" << DUMP_DEC_FORMAT( 5 ) << no << "] "
        << DUMP_HEX0x_FORMAT( 16 ) << value << " "
        << DUMP_HEX0x_FORMAT( 16 ) << size << " "
        << DUMP_STR_FORMAT( 7 ) << str_symbol_type( type ) << " "
        << DUMP_STR_FORMAT( 6 ) << str_symbol_bind( bind ) << " "
        << DUMP_STR_FORMAT( 9 ) << str_symbol_vis( other ) << " "
        << DUMP_STR_FORMAT( 6 ) << (shndx == 0 ? "UND" : std::to_string(shndx))  
        << "     " << DUMP_STR_FORMAT( 1 ) << name << " "
        << std::endl;
    std::cout.flags( original_flags );   
}                        


void show_banner()
{
    std::cout << "\n---------------------------------------------------------\n";
    std::cout << "[  Nr ] Value              Size               "
        "Type    Bind       Vis   Ndx"
    << "        Name" << std::endl;
}

void show_footer()
{
    std::cout << "\n---------------------------------------------------------\n";
}

class sym_update {
public:
    sym_update(FuncMap &funmap, const endianess_convertor& convertor, elfio& elf):
        funmap(funmap),convertor(convertor),elf(elf) {}

    uint32_t operator()(Elf_Xword index, const std::string& funcname, Elf32_Sym& sym)
    {
        process<Elf32_Sym>(index, funcname, sym);
        return 0;
    }
    uint32_t operator()(Elf_Xword index, const std::string& funcname, Elf64_Sym& sym)
    {
        process<Elf64_Sym>(index, funcname, sym);
        return 0;
    }

private:
    void update_value(Elf_Xword        index,
                    const std::string& funcname,
                    Elf64_Addr         &value,
                    Elf_Xword          &size,
                    unsigned char      &bind,
                    unsigned char      &type,
                    Elf_Half           &shndx,
                    unsigned char      &other)
    {
        uint32_t section_num = elf.sections.size();

        auto iter = funmap.find(funcname);
        if (iter == funmap.end()) {
            if (shndx > SHN_UNDEF && shndx < section_num) {
                const auto &section = elf.sections[shndx];
                //std::cout << "value = " << value << " address = " << section->get_address() << "\n";
                value = value - section->get_address();
            }
            return;
        }
        shndx = SHN_UNDEF;
        value = 0;
    }

    template <class T>
    void process(Elf_Xword index, const std::string& funcname, T& sym)
    {
        Elf64_Addr    value;
        Elf_Xword     size;
        unsigned char bind;
        unsigned char type;
        Elf_Half      shndx;
        unsigned char other;  

        convert_to_value(&sym, value, size, bind, type, shndx, other);
        show_symbol(index, funcname, value, size, bind, type, shndx, other);
        update_value(index, funcname, value, size, bind, type, shndx, other);
        convert_to_symbol(sym, value, size, bind, type, shndx, other);
        show_symbol(index, funcname, value, size, bind, type, shndx, other);
    }

    template <class T>
    void convert_to_value(const T* pSym,
                            Elf64_Addr&    value,
                            Elf_Xword&     size,
                            unsigned char& bind,
                            unsigned char& type,
                            Elf_Half&      shndx,
                            unsigned char& other )
    {
        value         = convertor( pSym->st_value );
        size          = convertor( pSym->st_size );
        bind          = ELF_ST_BIND( pSym->st_info );
        type          = ELF_ST_TYPE( pSym->st_info );
        shndx         = convertor( pSym->st_shndx );
        other         = pSym->st_other;
    }

    template <class T>
    void convert_to_symbol(T &entry,
                            Elf64_Addr&    value,
                            Elf_Xword&     size,
                            unsigned char& bind,
                            unsigned char& type,
                            Elf_Half&      shndx,
                            unsigned char& other )
    {
        // entry.st_name  = convertor( name );
        auto st_value = decltype( entry.st_value )( value );
        entry.st_value = convertor( st_value );
        auto st_size  = decltype( entry.st_size )( size );
        entry.st_size  = convertor( st_size );
        entry.st_info = decltype( entry.st_info )(ELF_ST_INFO(bind, type));
        entry.st_other = convertor( other );
        entry.st_shndx = convertor( shndx );
    }
private:
    FuncMap &funmap;
    const endianess_convertor& convertor;
    elfio& elf;
};

static void update_symbol_tables(FuncMap &funmap, elfio& reader)
{
    // nRet = generic_add_symbol<Elf32_Sym>( name, value, size, info, other, shndx );
    const endianess_convertor& convertor = reader.get_convertor();
    show_banner();
    sym_update updater(funmap, convertor, reader);
    if (reader.get_class() == ELFCLASS32) {
        for ( const auto& sec : reader.sections ) { // For all sections
            if (SHT_SYMTAB == sec->get_type() || SHT_DYNSYM == sec->get_type() ) {
                symbol_section_accessor symbols(reader, sec.get());           
                symbols.generic_update_symbols<Elf32_Sym>(updater);
                
            }
        }
    } else { // Elf64_Sym
        for ( const auto& sec : reader.sections ) { // For all sections
            if (SHT_SYMTAB == sec->get_type() || SHT_DYNSYM == sec->get_type() ) {
                symbol_section_accessor symbols(reader, sec.get());           
                symbols.generic_update_symbols<Elf64_Sym>(updater);
            }
        } 
    }
    show_footer();
}

void update_section(elfio& reader)
{
    std::cout << "------------update section section ---------------------\n";
    for ( const auto& sec : reader.sections ) { // For all sections
        if ( sec->get_address() != 0) {
            std::cout << "Section address = " << DUMP_HEX0x_FORMAT(16) << sec->get_address()
            << " change to 0! "
            << "section name : " << sec->get_name() << "\n";
            sec->set_address(0); 
        }
    } 
    std::cout << "------------update section section end ------------------\n"; 
}

void update_offset(elfio& reader, section *rel_sec, Elf_Sxword base)
{
    Elf64_Addr offset = 0;
    Elf_Word   symbol = 0;
    unsigned   rtype  = 0;
    Elf_Sxword addend = 0;
    relocation_section_accessor reloc(reader, rel_sec);
    for ( Elf_Word i = 0; i < reloc.get_entries_num(); i++ ) {
        reloc.get_entry( i, offset, symbol, rtype, addend );
        reloc.set_entry( i, offset + base, symbol, rtype, addend );
        std::cout << "offset = " << DUMP_HEX0x_FORMAT(16) << offset
           << " to = " << DUMP_HEX0x_FORMAT(16) << offset + base << "\n";
    }        
}


void update_reloc(elfio& reader)
{
    std::cout << "------------update reloc section ---------------------\n";
    for ( const auto& sec : reader.sections ) { // For all sections
        if (sec->get_type() == SHT_RELA) {
            int info = sec->get_info();
            if (info != 0) {
                auto *section = reader.sections[info];
                auto base = section->get_address();
                std::cout << sec->get_name() << " : " << section->get_name() 
                << " base = " << DUMP_HEX0x_FORMAT(16) << base << "\n";
                update_offset(reader, sec.get(), 0 - base);
            }
        }
    } 
    std::cout << "------------update reloc section end-------------------\n"; 
}



int main( int argc, char** argv )
{
    if ( argc != 3 ) {
        std::cout << "Usage: relocelf elf_name func_list.txt\n";
        return 1;
    }

    std::string elfname = argv[1];
    std::string funcname = argv[2];

    FuncMap funcset = GetFuncMap(funcname);

    elfio reader;

    if ( !reader.load( elfname ) ) {
        std::cerr << "File " << elfname
                  << " is not found or it is not an ELF file\n";
        return 1;
    } 
    
    std::cout << "Open file " << elfname << " OK! type is " << 
    reader.get_type() << "(ET_NONE:0, ET_REL:1, ET_EXEC:2, ET_DYN:3, ET_CORE: 4); \n";
    
    update_symbol_tables(funcset, reader);

    update_reloc(reader);

    update_section(reader);

    reader.set_type(1);
    reader.set_entry(0);
    std::string newelf = std::string("reloc_") + elfname;
    reader.segments.clear();
    auto succ = reader.save(newelf);
    if (succ) {
        std::cout << "Save file to " << newelf << " success.\n";
    } else {
        std::cout << "Save file to " << newelf << " failed!!!\n";
    }

    return 0;
}

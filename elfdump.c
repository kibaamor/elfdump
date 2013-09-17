/*
 * Copyright (c) 2013 Kiba Amor <KibaAmor@gmai.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list ofconditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materialsprovided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef _countof
#define _countof(X) (sizeof(X)/sizeof(X[0]))
#endif

#define safe_free(X) \
  if (X != NULL) \
  { \
    free(X); \
    X = NULL; \
  }

#if defined(__x86_64__)
#define ARCH "x86_64"
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym  Elf_Sym;
#define ELF_ST_TYPE(X) ELF64_ST_TYPE(X)
#define ELF_ST_BIND(X) ELF64_ST_BIND(X)
#define ELF_ST_VISIBILITY(X) ELF64_ST_VISIBILITY(X)
typedef Elf64_Rel  Elf_Rel;
typedef Elf64_Rela Elf_Rela;
#define ELF_R_SYM(X)  ELF64_R_SYM(X)
#define ELF_R_TYPE(X) ELF64_R_TYPE(X)
#else
#define ARCH "x86"
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Sym  Elf_Sym;
#define ELF_ST_TYPE(X) ELF32_ST_TYPE(X)
#define ELF_ST_BIND(X) ELF32_ST_BIND(X)
#define ELF_ST_VISIBILITY(X) ELF32_ST_VISIBILITY(X)
typedef Elf32_Rel  Elf_Rel;
typedef Elf32_Rela Elf_Rela;
#define ELF_R_SYM(X)  ELF32_R_SYM(X)
#define ELF_R_TYPE(X) ELF32_R_TYPE(X)
#endif // __x86_64__

typedef struct
{
  int         key;
  const char* value;
} pair_t;

const char* g_selfname = NULL;
const char* g_filename = NULL;
int         g_file = -1;
Elf_Ehdr*   g_ehdr = NULL;
Elf_Phdr*   g_phdrs = NULL;
int         g_phdr_num = -1;
Elf_Shdr*   g_shdrs = NULL;
int         g_shdr_num = -1;
char*       g_shdr_str_tab = NULL;

void clean_up(void)
{
  if (g_file >= 0)
  {
    close(g_file);
    g_file = -1;
  }
  safe_free(g_ehdr);
  safe_free(g_phdrs);
  safe_free(g_shdrs);
  safe_free(g_shdr_str_tab);
}

int get_file(void)
{
  if (g_file < 0)
  {
    g_file = open(g_filename, O_RDONLY);
    if (g_file < 0)
    {
      perror("open input file failed");
      exit(EXIT_FAILURE);
    }
  }

  return g_file;
}

int read_at(int file, int pos, void* buf, int cnt)
{
  if (pos == lseek(file, pos, SEEK_SET))
    return read(file, buf, cnt) == cnt ? cnt : -1;
  return -1;
}

int is_elf_file(unsigned char* ident)
{
  if (!ident
      || ident[EI_MAG0] != ELFMAG0
      || ident[EI_MAG1] != ELFMAG1
      || ident[EI_MAG2] != ELFMAG2
      || ident[EI_MAG3] != ELFMAG3)
  {
    return 0;
  }
  return 1;
}

const Elf_Ehdr* get_ehdr(void)
{
  if (g_ehdr == NULL)
  {
    g_ehdr = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
    if (read_at(get_file(), 0, g_ehdr, sizeof(Elf_Ehdr)) < 0)
    {
      perror("read elf header failed\n");
      exit(EXIT_FAILURE);
    }
    else if (!is_elf_file(g_ehdr->e_ident))
    {
      fprintf(stderr, "'%s' is not a elf file\n", g_filename);
      exit(EXIT_FAILURE);
    }
    if (sizeof(Elf_Ehdr) != g_ehdr->e_ehsize)
    {
      fprintf(stderr, "elf header size mismatch\n");
      exit(EXIT_FAILURE);
    }
  }

  return g_ehdr;
}

const Elf_Phdr* get_phdrs(void)
{
  const Elf_Ehdr* ehdr = NULL;
  if (g_phdrs == NULL)
  {
    ehdr = get_ehdr();
    if (sizeof(Elf_Phdr) != ehdr->e_phentsize)
    {
      fprintf(stderr, "program header size mismatch\n");
      exit(EXIT_FAILURE);
    }
    g_phdr_num = ehdr->e_phnum;
    g_phdrs = (Elf_Phdr *)malloc(sizeof(Elf_Phdr) * g_phdr_num);
    if (read_at(get_file(), ehdr->e_phoff, g_phdrs, 
        sizeof(Elf_Phdr) * g_phdr_num) < 0)
    {
      perror("read program header failed\n");
      exit(EXIT_FAILURE);
    }
  }
  return g_phdrs;
}

const Elf_Shdr* get_shdrs(void)
{
  const Elf_Ehdr* ehdr = NULL;
  if (g_shdrs == NULL)
  {
    ehdr = get_ehdr();
    if (sizeof(Elf_Shdr) != ehdr->e_shentsize)
    {
      fprintf(stderr, "section header size mismatch\n");
      exit(EXIT_FAILURE);
    }
    g_shdr_num = ehdr->e_shnum;
    g_shdrs = (Elf_Shdr *)malloc(sizeof(Elf_Shdr) * g_shdr_num);
    if (read_at(get_file(), ehdr->e_shoff, g_shdrs,
          sizeof(Elf_Shdr) * g_shdr_num) < 0)
    {
      perror("read section header failed");
      exit(EXIT_FAILURE);
    }
  }
  return g_shdrs;
}

void* get_sect_cont_by_idx(int sect_idx)
{
  const Elf_Shdr* shdrs = NULL;
  void* sect_cont = NULL;

  if (sect_idx < 0 || sect_idx >= g_shdr_num)
    return NULL;

  shdrs = get_shdrs();
  sect_cont = (void *)malloc(shdrs[sect_idx].sh_size);

  if (read_at(get_file(), shdrs[sect_idx].sh_offset, 
    sect_cont, shdrs[sect_idx].sh_size) < 0)
  {
    safe_free(sect_cont);
    return NULL;
  }

  return sect_cont;
}

const char* get_shdr_str_tab(void)
{
  if (g_shdr_str_tab == NULL)
    g_shdr_str_tab = get_sect_cont_by_idx(get_ehdr()->e_shstrndx);
  return g_shdr_str_tab;
}

int get_sect_idx_by_name(const char* sect_name)
{
  const Elf_Shdr* shdrs = get_shdrs();
  const char* shdr_str_tab = get_shdr_str_tab();
  int i = 0;

  for (i = 0; i < g_shdr_num; ++i)
  {
    if (strcmp(sect_name, shdrs[i].sh_name + shdr_str_tab) == 0)
      return i;
  }

  return -1;
}

void print_pair(int key, const pair_t* pairs, int cnt, int linefeed)
{
  while (--cnt >= 0)
  {
    if (key == pairs[cnt].key)
    {
      printf("%s", pairs[cnt].value);
      break;
    }
  }
  if (linefeed)
    printf("\n");
}

void print_ehdr_ident(void)
{
  const pair_t classpairs[] = 
  {
    {ELFCLASSNONE,  "None"},
    {ELFCLASS32,    "ELF32"},
    {ELFCLASS64,    "ELF64"},
  };
  const pair_t datapairs[] =
  {
    {ELFDATANONE, "None"},
    {ELFDATA2LSB, "2's complement, little endian"},
    {ELFDATA2MSB, "2's complement, big endian"},
  };
  const pair_t osabipairs[] =
  {
    //{ELFOSABI_NONE,     "UNIX System VB ABI"},
    {ELFOSABI_SYSV,       "UNIX System VB ABI"},
    {ELFOSABI_HPUX,       "HP-UX"},
    {ELFOSABI_NETBSD,     "NetBSD"},
    //{ELFOSABI_GNU,      "Object uses GNU ELF extensions"},
    {ELFOSABI_LINUX,      "Object uses GNU ELF extensions"},
    {ELFOSABI_SOLARIS,    "Sun Solaris"},
    {ELFOSABI_AIX,        "AIX"},
    {ELFOSABI_IRIX,       "IBM Irix"},
    {ELFOSABI_FREEBSD,    "FreeBSD"},
    {ELFOSABI_TRU64,      "Compaq TRU64 UNIX"},
    {ELFOSABI_MODESTO,    "Novell Modesto"},
    {ELFOSABI_OPENBSD,    "OpenBSD"},
    {ELFOSABI_ARM_AEABI,  "ARM EABI"},
    {ELFOSABI_ARM,        "ARM"},
    {ELFOSABI_STANDALONE, "Standlone (embedded) application"},
  };
  const Elf_Ehdr* ehdr = get_ehdr();
  const unsigned char* ident = ehdr->e_ident;
  int i = 0;

  printf("ELF Header:\n  Magic:  ");
  for (i = 0; i < EI_NIDENT; ++i)  
    printf("%02X ", ident[i]);

  printf("\n  Class:                              ");
  print_pair(ident[EI_CLASS], classpairs, _countof(classpairs), 1);

  printf("  Data:                               ");
  print_pair(ident[EI_DATA], datapairs, _countof(datapairs), 1);

  printf("  Version:                            %d%s\n", ident[EI_VERSION],
      ident[EI_VERSION] == EV_CURRENT ? "(current)" : "");

  printf("  OS/ABI:                             ");
  print_pair(ident[EI_OSABI], osabipairs, _countof(osabipairs), 1);
}

void print_ehdr(void)
{
  const pair_t objtypepairs[] = 
  {
    {ET_NONE, "None"},
    {ET_REL,  "Relocatable file"},
    {ET_EXEC, "Executable file"},
    {ET_DYN,  "Shared object file"},
    {ET_CORE, "Core file"},
  };
  const pair_t machinepairs[] = 
  {
    {EM_NONE,       "None"},
    {EM_M32,        "AT&T WE 32100"},
    {EM_SPARC,      "SUN SPARC"},
    {EM_386,        "Intel 80386"},
    {EM_68K,        "Motorola m68k family"},
    {EM_88K,        "Motorola m88k family"},
    {EM_860,        "Intel 80860"},
    {EM_MIPS,       "MIPS R3000 big-endian"},
    {EM_S370,       "IBM System/370"},
    {EM_MIPS_RS3_LE,"MIPS R3000 little-endian"},
    {EM_PARISC,     "HPPA"},
    {EM_VPP500,     "Fujitsu VPP500"},
    {EM_SPARC32PLUS,"Sun's \"v8plus\""},
    {EM_960,        "Intel 80960"},
    {EM_PPC,        "PowerPC"},
    {EM_PPC64,      "PowerPC 64-bit"},
    {EM_S390,       "IBM S390"},
    {EM_V800,       "NEC V800 series"},
    {EM_FR20,       "Fujitsu FR20"},
    {EM_RH32,       "TRW RH-32"},
    {EM_RCE,        "Motorola RCE"},
    {EM_ARM,        "ARM"},
    {EM_FAKE_ALPHA, "Digital Alpha"},
    {EM_SH,         "Hitachi SH"},
    {EM_SPARCV9,    "SPARC v9 64-bit"},
    {EM_TRICORE,    "Siemens Tricore"},
    {EM_ARC,        "Argonaut RISC Core"},
    {EM_H8_300,     "Hitachi H8/300"},
    {EM_H8_300H,    "Hitachi H8/300H"},
    {EM_H8S,        "Hitachi H8S"},
    {EM_H8_500,     "Hitachi H8/500"},
    {EM_IA_64,      "Intel Merced"},
    {EM_MIPS_X,     "Stanford MIPS-X"},
    {EM_COLDFIRE,   "Motorola Coldfire"},
    {EM_68HC12,     "Motorola M68HC12"},
    {EM_MMA,        "Fujitsu MMA Multimedia Accelerator"},
    {EM_PCP,        "Siemens PCP"},
    {EM_NCPU,       "Sony nCPU embeeded RISC"},
    {EM_NDR1,       "Denso NDR1 microprocessor"},
    {EM_STARCORE,   "Motorola Start*Core processor"},
    {EM_ME16,       "Toyota ME16 processor"},
    {EM_ST100,      "STMicroelectronic ST100 processor"},
    {EM_TINYJ,      "Advanced Logic Corp. Tinyj emb.fam"},
    {EM_X86_64,     "AMD x86-64 architecture"},
    {EM_PDSP,       "Sony DSP Processor"},
    {EM_FX66,       "Siemens FX66 microcontroller"},
    {EM_ST9PLUS,    "STMicroelectronics ST9+ 8/16 mc"},
    {EM_ST7,        "STmicroelectronics ST7 8 bit mc"},
    {EM_68HC16,     "Motorola MC68HC16 microcontroller"},
    {EM_68HC11,     "Motorola MC68HC11 microcontroller"},
    {EM_68HC08,     "Motorola MC68HC08 microcontroller"},
    {EM_68HC05,     "Motorola MC68HC05 microcontroller"},
    {EM_SVX,        "Silicon Graphics SVx"},
    {EM_ST19,       "STMicroelectronics ST19 8 bit mc"},
    {EM_VAX,        "Digital VAX"},
    {EM_CRIS,       "Axis Communications 32-bit embedded processor"},
    {EM_JAVELIN,    "Infineon Technologies 32-bit embedded processor"},
    {EM_FIREPATH,   "Element 14 64-bit DSP Processor"},
    {EM_ZSP,        "LSI Logic 16-bit DSP Processor"},
    {EM_MMIX,       "Donald Knuth's educational 64-bit processor"},
    {EM_HUANY,      "Harvard University machine-independent object files"},
    {EM_PRISM,      "SiTera Prism"},
    {EM_AVR,        "Atmel AVR 8-bit microcontroller"},
    {EM_FR30,       "Fujitsu FR30"},
    {EM_D10V,       "Mitsubishi D10V"},
    {EM_D30V,       "Mitsubishi D30V"},
    {EM_V850,       "NEC v850"},
    {EM_M32R,       "Mitsubishi M32R"},
    {EM_MN10300,    "Matsushita MN10300"},
    {EM_MN10200,    "Matsushita MN10200"},
    {EM_PJ,         "picoJava"},
    {EM_OPENRISC,   "OpenRISC 32-bit embedded processor"},
    {EM_ARC_A5,     "ARC Cores Tangent-A5"},
    {EM_XTENSA,     "Tensilica Xtensa Architecture"},
  };
  const pair_t versionpairs[] =
  {
    {EV_NONE,     "None"},
    {EV_CURRENT,  "Current version"},
  };
  const Elf_Ehdr* ehdr = get_ehdr();

  print_ehdr_ident();

  printf("  Object file type:                   ");
  print_pair(ehdr->e_type, objtypepairs, _countof(objtypepairs), 1);

  printf("  Machine:                            ");
  print_pair(ehdr->e_machine, machinepairs, _countof(machinepairs), 1);

  printf("  Version:                            ");
  print_pair(ehdr->e_version, versionpairs, _countof(versionpairs), 1);

  printf("  Entry point address:                0x%08x\n", ehdr->e_entry);
  printf("  Start of program headers:           0x%08x (bytes into file)\n", ehdr->e_phoff);
  printf("  Start of section headers:           0x%08x (bytes into file)\n", ehdr->e_shoff);
  printf("  Flags:                              0x%08x\n", ehdr->e_flags);
  printf("  Size of this header:                %d (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:            %d (bytes)\n", ehdr->e_phentsize);
  printf("  Number of program headers:          %d\n", ehdr->e_phnum);
  printf("  Size of section headers:            %d (bytes)\n", ehdr->e_shentsize);
  printf("  Number of section headers:          %d\n", ehdr->e_shnum);
  printf("  Section header string table index:  %d\n\n", ehdr->e_shstrndx);
}

void print_phdrs(void)
{
  const pair_t typepairs[] = 
  {
    {PT_NULL,         "NULL        "},
    {PT_LOAD,         "LOAD        "},
    {PT_DYNAMIC,      "DYNAMIC     "},
    {PT_INTERP,       "INTERP      "},
    {PT_NOTE,         "NOTE        "},
    {PT_SHLIB,        "SHLIB       "},
    {PT_PHDR,         "PHDR        "},
    {PT_TLS,          "TLS         "},
    {PT_GNU_EH_FRAME, "GNU_EH_FRAME"},
    {PT_GNU_STACK,    "GUN_STACK   "},
    {PT_GNU_RELRO,    "GNU_RELRO   "},
  };
  const Elf_Phdr* phdrs = get_phdrs();
  int i;
  char tmp_buf[16];

  printf("Program Headers:\n");
  printf("  Type         Offset     VirtAddr   PhysAddr   FileSize   MemSize    Flag Align\n");
  for (i = 0; i < g_phdr_num; ++i)
  {
    printf("  ");
    print_pair(phdrs[i].p_type, typepairs, _countof(typepairs), 0);

    printf(" 0x%08x", phdrs[i].p_offset);

    printf(" 0x%08x", phdrs[i].p_vaddr);
    printf(" 0x%08x", phdrs[i].p_paddr);

    printf(" 0x%08x", phdrs[i].p_filesz);
    printf(" 0x%08x", phdrs[i].p_memsz);
    snprintf(tmp_buf, 16, "%s%s%s",
        phdrs[i].p_flags & PF_X ? "X" : "",
        phdrs[i].p_flags & PF_W ? "W" : "",
        phdrs[i].p_flags & PF_R ? "R" : "");
    printf(" %-4s", tmp_buf);
    printf(" 0x%04x\n", phdrs[i].p_align);
  }
  printf("\n");
}

void print_shdrs(void)
{
  const pair_t typepairs[] =
  {
    {SHT_NULL,            "NULL          "},
    {SHT_PROGBITS,        "PROGBITS      "},
    {SHT_SYMTAB,          "SYMTAB        "},
    {SHT_STRTAB,          "STRTAB        "},
    {SHT_RELA,            "RELA          "},
    {SHT_HASH,            "HASH          "},
    {SHT_DYNAMIC,         "DYNAMIC       "},
    {SHT_NOTE,            "NOTE          "},
    {SHT_NOBITS,          "NOBITS        "},
    {SHT_REL,             "REL           "},
    {SHT_SHLIB,           "SHLIB         "},
    {SHT_DYNSYM,          "DYNSYM        "},
    {SHT_INIT_ARRAY,      "INIT_ARRAY    "},
    {SHT_FINI_ARRAY,      "FINI_ARRAY    "},
    {SHT_PREINIT_ARRAY,   "PREINIT_ARRAY "},
    {SHT_GROUP,           "GROUP         "},
    {SHT_SYMTAB_SHNDX,    "SYMTAB_SHNDX  "},
    {SHT_GNU_ATTRIBUTES,  "GNU_ATTRIBUTES"},
    {SHT_GNU_HASH,        "GNU_HASH      "},
    {SHT_GNU_LIBLIST,     "GNU_LIBLIST   "},
    {SHT_GNU_verdef,      "GNU_verdef    "},
    {SHT_GNU_verneed,     "GNU_verneed   "},
    {SHT_GNU_versym,      "GNU_versym    "},
  };
  const Elf_Shdr* shdrs = get_shdrs();
  const char* shdr_str_tab = get_shdr_str_tab();
  int i;
  char tmp_buf[16];

  printf("Section Headers:\n");
  printf("  Idx Name               Type           Flags VirtAddr   Offset     Size       Link Info Align  EntrySize\n");
  for (i = 0; i < g_shdr_num; ++i)
  {
    printf(" %- 3d ", i);
    printf(" %-18s ", shdr_str_tab + shdrs[i].sh_name);
    print_pair(shdrs[i].sh_type, typepairs, _countof(typepairs), 0);
    snprintf(tmp_buf, 16, " %s%s%s%s%s%s%s%s%s%s",
        shdrs[i].sh_flags & SHF_WRITE             ? "W" : "",
        shdrs[i].sh_flags & SHF_ALLOC             ? "A" : "",
        shdrs[i].sh_flags & SHF_EXECINSTR         ? "E" : "",
        shdrs[i].sh_flags & SHF_MERGE             ? "M" : "",
        shdrs[i].sh_flags & SHF_STRINGS           ? "S" : "",
        shdrs[i].sh_flags & SHF_INFO_LINK         ? "I" : "",
        shdrs[i].sh_flags & SHF_LINK_ORDER        ? "L" : "",
        shdrs[i].sh_flags & SHF_OS_NONCONFORMING  ? "O" : "",
        shdrs[i].sh_flags & SHF_GROUP             ? "G" : "",
        shdrs[i].sh_flags & SHF_TLS               ? "T" : "");
    printf("%-5s ", tmp_buf);
    printf(" 0x%08x", shdrs[i].sh_addr);
    printf(" 0x%08x", shdrs[i].sh_offset);
    printf(" 0x%08x", shdrs[i].sh_size);
    printf("%- 4d ", shdrs[i].sh_link);
    printf("%- 4d ", shdrs[i].sh_info);
    printf(" 0x%04x", shdrs[i].sh_addralign);
    printf(" 0x%08x\n", shdrs[i].sh_entsize);
  }
  printf("Key to Flags:\n");
  printf("  W (Writable), A (Alloc), E(Executable), M (Merge), S (Strings),\n");
  printf("  I (Info), L (Link Order), O (Os Nonconforming), G (Group), T (TLS)\n\n");
}

void print_symbol_info_by_sect_idx(int sect_idx)
{
  const pair_t typepairs[] = 
  {
    {STT_NOTYPE,    "NOTYPE   "},
    {STT_OBJECT,    "OBJECT   "},
    {STT_FUNC,      "FUNC     "},
    {STT_SECTION,   "SECTION  "},
    {STT_FILE,      "FILE     "},
    {STT_COMMON,    "COMMON   "},
    {STT_TLS,       "TLS      "},
    {STT_GNU_IFUNC, "GUN_IFUNC"},
  };
  const pair_t bindpairs[] = 
  {
    {STB_LOCAL,       "LOCAL     "},
    {STB_GLOBAL,      "GLOBAL    "},
    {STB_WEAK,        "WEAK      "},
    {STB_GNU_UNIQUE,  "GUN_UNIQUE"},
  };
  const pair_t visiblepairs[] =
  {
    {STV_DEFAULT,   "DEFAULT   "},
    {STV_INTERNAL,  "INTERNAL  "},
    {STV_HIDDEN,    "HIDDEN    "},
    {STV_PROTECTED, "PROTECTED "},
  };
  const Elf_Shdr* shdrs = get_shdrs();
  const char* shdr_str_tab = get_shdr_str_tab();
  Elf_Sym* symbol = (Elf_Sym *)get_sect_cont_by_idx(sect_idx);
  int symbol_num = shdrs[sect_idx].sh_size / sizeof(Elf_Sym);
  char* symbol_str_tab = (char *)get_sect_cont_by_idx(shdrs[sect_idx].sh_link);
  int i = 0;

  if (symbol == NULL
    || symbol_str_tab == NULL)
  {
    safe_free(symbol);
    safe_free(symbol_str_tab);
    return;
  }

  printf("Symbol Info For '%s':\n", shdrs[sect_idx].sh_name + shdr_str_tab);
  printf("  Idx Value      Size   Type      Bind       Visibility Shndx  Name\n");
  for (i = 0; i < symbol_num; ++i)
  {
    printf("  %3d", i);
    printf(" 0x%08x", symbol[i].st_value);
    printf(" 0x%04x ", symbol[i].st_size);
    print_pair(ELF_ST_TYPE(symbol[i].st_info), typepairs, _countof(typepairs), 0);
    printf(" ");
    print_pair(ELF_ST_BIND(symbol[i].st_info), bindpairs, _countof(bindpairs), 0);
    printf(" ");
    print_pair(ELF_ST_VISIBILITY(symbol[i].st_other), visiblepairs, _countof(visiblepairs), 0);
    printf(" ");
    switch (symbol[i].st_shndx)
    {
      case SHN_UNDEF:
        printf("UNDEF ");
        break;
      case SHN_ABS:
        printf("ABS   ");
        break;
      case SHN_COMMON:
        printf("COMMON");
        break;
      default:
        printf("%-6d", symbol[i].st_shndx);
        break;
    }
    printf(" %s\n", symbol[i].st_name + symbol_str_tab);
  }

  safe_free(symbol);
  safe_free(symbol_str_tab);
}

void print_symbol_info(void)
{
  const Elf_Shdr* shdrs = get_shdrs();
  int i = 0;

  printf("Symbol Info:\n");
  for (i = 0; i < g_shdr_num; ++i)
  {
    if (shdrs[i].sh_type == SHT_SYMTAB 
      || shdrs[i].sh_type == SHT_DYNSYM)
    {
      print_symbol_info_by_sect_idx(i);
    }
  }
}

void print_relocation_info(void)
{ 
  const Elf_Shdr* shdrs = get_shdrs();
  const char* shdr_str_tab = get_shdr_str_tab();
  Elf_Rel* rel = NULL;
  int rel_num = 0;
  Elf_Sym* sym = NULL;
  char* sym_str_tab = NULL;
  int i = 0;
  int j = 0;

  printf("Relocation Info:\n");
  for (i = 0; i < g_shdr_num; ++i)
  {
    if (shdrs[i].sh_type == SHT_REL)
    {
      printf("Relocation Info Without Addends For '%s':\n", 
          shdrs[shdrs[i].sh_info].sh_name + shdr_str_tab);

      rel_num = shdrs[i].sh_size / sizeof(Elf_Rel);
      rel = (Elf_Rel *)get_sect_cont_by_idx(i);
      sym = (Elf_Sym *)get_sect_cont_by_idx(shdrs[i].sh_link);
      sym_str_tab = (char *)get_sect_cont_by_idx(shdrs[shdrs[i].sh_link].sh_link);

      printf("  OFFSET     TYPE       VALUE\n");
      for (j = 0; j < rel_num; ++j)
      {
        printf("  0x%08x", rel[j].r_offset);
        printf(" 0x%08x", ELF_R_TYPE(rel[j].r_info));
        printf(" %s\n", sym[ELF_R_SYM(rel[j].r_info)].st_name + sym_str_tab);
      }

      safe_free(rel);
      safe_free(sym);
      safe_free(sym_str_tab);
    }
  }
}

void print_all_str_tab(void)
{
  const Elf_Shdr* shdrs = get_shdrs();
  const char* shdr_str_tab = get_shdr_str_tab();
  char* str_tab = NULL;
  int str_tab_pos = 0;
  int i = 0;
  int j = 0;

  printf("All String Table:\n");
  for (i = 0; i < g_shdr_num; ++i)
  {
    if (shdrs[i].sh_type == SHT_STRTAB) 
    {
      printf("String Table '%s':\n", shdrs[i].sh_name + shdr_str_tab);
      printf("  Idx Value\n");

      str_tab = (char *)get_sect_cont_by_idx(i);
      for (j = 0, str_tab_pos = 0; str_tab_pos < shdrs[i].sh_size; ++j)
      {
        printf("  %3d %s\n", j, str_tab + str_tab_pos);
        str_tab_pos += strlen(str_tab + str_tab_pos) + 1;
      }
      safe_free(str_tab);
    }
  }
}

void print_usage(void)
{
  fprintf(stderr, "Usage: %s file\n", g_selfname);
  fprintf(stderr, " -a  same as -h -p -s -S -r -d\n");
  fprintf(stderr, " -h  dump ELF file header\n");
  fprintf(stderr, " -p  dump ELF file program header\n");
  fprintf(stderr, " -s  dump ELF file section header\n");
  fprintf(stderr, " -S  dump Symbol Info\n");
  fprintf(stderr, " -r  dump relocation info\n");
  fprintf(stderr, " -d  dump all string table\n");
  fprintf(stderr, " -v  print version info and exit\n");
}

void print_version(void)
{
  printf("Elf(Executable Linkable Format) file dump tool("ARCH")\n");
  printf("Copyright (c) 2013 Kiba Amor <KibaAmor@gmai.com>\n");
  printf("All rights reserved.\n");
  printf("Version 1.0\n");
}

int main(int argc, char** argv)
{
  int i = 0;
  int j = 0;
  int show_ehdr = 0;
  int show_phdrs = 0;
  int show_shdrs = 0;
  int show_symbol_info = 0;
  int show_relocation_info = 0;
  int show_all_str_tab = 0;

  g_selfname = argv[0];

  for (i = 1; i < argc; ++i)
  {
    if (argv[i][0] != '-')
    {
      if (g_filename != NULL)
      {
        fprintf(stderr, "multi input file detected\n");
        return EXIT_FAILURE;
      }
      else
      {
        g_filename = argv[i];
        continue;
      }
    }

    for (j = (int)strlen(argv[i]) - 1; j > 0 ; --j)
    {
      switch (argv[i][j])
      {
        case 'a':
          show_ehdr = 1;
          show_phdrs = 1;
          show_shdrs = 1;
          show_symbol_info = 1;
          show_relocation_info = 1;
          show_all_str_tab = 1;
          break;
        case 'h':
          show_ehdr = 1;
          break;
        case 'p':
          show_phdrs = 1;
          break;
        case 's':
          show_shdrs = 1;
          break;
        case 'S':
          show_symbol_info = 1;
          break;
        case 'r':
          show_relocation_info = 1;
          break;
        case 'd':
          show_all_str_tab = 1;
          break;
        case 'v':
          print_version();
          return EXIT_FAILURE;
        default:
          fprintf(stderr, "unkown option: '%c'\n", argv[i][j]);
          return EXIT_FAILURE;
      }
    }
  }

  if (g_filename == NULL
      || (show_ehdr == 0
      && show_phdrs == 0
      && show_shdrs == 0 
      && show_symbol_info == 0
      && show_relocation_info == 0
      && show_all_str_tab == 0))
  {
    print_usage();
    return EXIT_FAILURE;
  }

  atexit(clean_up);

  if (show_ehdr)
    print_ehdr();
  if (show_phdrs)
    print_phdrs();
  if (show_shdrs)
    print_shdrs();
  if (show_symbol_info)
    print_symbol_info();
  if (show_relocation_info)
    print_relocation_info();
  if (show_all_str_tab)
    print_all_str_tab();

  return EXIT_SUCCESS;
}

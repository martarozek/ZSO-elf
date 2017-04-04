#define _GNU_SOURCE

#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "interceptor.h"

#define Elf_Phdr  Elf64_Phdr
#define Elf_Dyn   Elf64_Dyn
#define Elf_Rela  Elf64_Rela
#define Elf_Addr  Elf64_Addr
#define Elf_Xword Elf64_Xword
#define Elf_Sym   Elf64_Sym

typedef void *ifunc(void);

typedef struct Intercept_Data{
    const char *func_name;
    void *func_ptr;
} Intercept_Data;

const char *get_sym_name(const Elf_Sym *sym, const char *strtab_base) {
    return strtab_base + sym->st_name;
}

static int find_symbol(struct dl_phdr_info *info, size_t size, void *data) {
    Elf_Sym *symtab_base;
    char *strtab_base;
    bool vdso = true;

    Elf_Phdr *phdr = (Elf_Phdr *) info->dlpi_phdr;

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf_Dyn *dyn_entry = (Elf_Dyn *) (info->dlpi_addr + phdr[i].p_vaddr);
            for (int j = 0; dyn_entry[j].d_tag != DT_NULL; ++j) {
                if (dyn_entry[j].d_tag == DT_STRTAB) {
                    strtab_base = (char *) dyn_entry[j].d_un.d_ptr;
                }
                else if (dyn_entry[j].d_tag == DT_SYMTAB) {
                    symtab_base = (Elf_Sym *) dyn_entry[j].d_un.d_ptr;
                }
                else if (dyn_entry[j].d_tag == DT_JMPREL) {
                    vdso = false;
                }
            }
            break;
        }
    }

    Intercept_Data *intercept_data = (Intercept_Data *) data;

    if (!vdso) {
        Elf_Sym *sym = symtab_base;
        while ((Elf_Addr) sym < (Elf_Addr) strtab_base) {
            if (strcmp(get_sym_name(sym, strtab_base), intercept_data->func_name) == 0) {
                if (sym->st_shndx != SHN_UNDEF) {
                    if (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC) {
                        intercept_data->func_ptr = ((ifunc *) (info->dlpi_addr + sym->st_value))();
                    } else {
                        intercept_data->func_ptr = (void *) (info->dlpi_addr + sym->st_value);
                    }
                    return 1;
                }
            }
            ++sym;
        }
    }

    return 0;
}

static int replace_function(struct dl_phdr_info *info, size_t size, void *data) {
    Elf_Rela *plt_base;
    Elf_Sym *symtab_base;
    char *strtab_base;
    Elf_Xword plt_sz = 0, plt_ent_sz = 0;

    Elf_Phdr *phdr = (Elf_Phdr *) info->dlpi_phdr;

    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf_Dyn *dyn = (Elf_Dyn *) (info->dlpi_addr + phdr[i].p_vaddr);
            for (int j = 0; dyn[j].d_tag != DT_NULL; ++j) {
                if (dyn[j].d_tag == DT_PLTRELSZ) {
                    plt_sz = (Elf_Xword) dyn[j].d_un.d_val;
                }
                else if (dyn[j].d_tag == DT_RELAENT) {
                    plt_ent_sz = (Elf_Xword) dyn[j].d_un.d_val;
                }
                else if (dyn[j].d_tag == DT_JMPREL) {
                    plt_base = (Elf_Rela *) dyn[j].d_un.d_ptr;
                }
                else if (dyn[j].d_tag == DT_STRTAB) {
                    strtab_base = (char *) dyn[j].d_un.d_ptr;
                }
                else if (dyn[j].d_tag == DT_SYMTAB) {
                    symtab_base = (Elf_Sym *) dyn[j].d_un.d_ptr;
                }
            }
            break;
        }
    }

    Elf_Xword plt_ent_cnt = 0;
    if (plt_sz && plt_ent_sz) {
        plt_ent_cnt = plt_sz / plt_ent_sz;
    }

    Intercept_Data *intercept_data = (Intercept_Data *) data;

    for (int i = 0; i < plt_ent_cnt; ++i) {
        Elf_Rela *plt_entry = plt_base + i;
        if (ELF64_R_TYPE(plt_entry->r_info) == R_X86_64_JUMP_SLOT) {
            Elf_Sym *sym = symtab_base + ELF64_R_SYM(plt_entry->r_info);
            if (strcmp(get_sym_name(sym, strtab_base), intercept_data->func_name) == 0) {
                Elf_Addr got = info->dlpi_addr + plt_entry->r_offset;
                *(void**) got = intercept_data->func_ptr;
                break;
            }
        }
    }

    return 0;
}

void *intercept_function(const char *name, void *new_func) {
    Intercept_Data data = { .func_name = name, .func_ptr = new_func };
    dl_iterate_phdr(replace_function, (void *) &data);
    data.func_ptr = NULL;
    dl_iterate_phdr(find_symbol, (void *) &data);
    return data.func_ptr;
}

void unintercept_function(const char *name) {
    Intercept_Data data = { .func_name = name, .func_ptr = NULL };
    dl_iterate_phdr(find_symbol, (void *) &data);
    dl_iterate_phdr(replace_function, (void *) &data);
}

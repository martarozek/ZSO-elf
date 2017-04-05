Zadanie 1 - ELF
Marta Rożek
360953

Szukanie funkcji w tablicach symboli:
- żeby poznać rozmiar symtab zakładam, że po symtab występuje strtab; dzięki temu iteruję po symtab i pomijam temat haszowania;
- aby uniknąć problemu z vdso sprawdzam czy adres obiektu zgadza się z adresem zwróconym przez getauxval(AT_SYSINFO_EHDR);
- pomijam symbole oznaczone SHN_UNDEF;
- symbole oznaczone STT_GNU_IFUNC rezolwuję;

Podstawianie funkcji w got:
- znajduję rekord w tablicy plt o typie R_X86_64_JUMP_SLOT i zadanej nazwie symbolu;
- w odpowiadającym wpisie w GOT wstawiam adres nowej funkcji;


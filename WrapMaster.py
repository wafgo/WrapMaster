# Author: Wadim Mueller <wafgo01@gmail.com>
import sys
import os
try:
    import lief
except ImportError:
    print('LIEF is not installed. Either install it via "pip install lief", or use the virtualenv via "source env/activate.sh"')
    sys.exit(1)
import argparse
import logging

logging.basicConfig(level=logging.WARNING)

script_version_major = "0"
script_version_minor = "2"
script_version_patch = "0"

script_version = 'v' + script_version_major + '.' + script_version_minor + '.' + script_version_patch

def make_undef_wrap_symbol(name):
    """
    creates an UNDEF symbol so it can be connected to the relocation. This is only needed if you want to wrap
    a function call from within the same compilation unit.
    This is basically the whole point why this tool was made. GNU ld (maybe also LLVM LLD) only allows to
    wrap functions with the --wrap=XX parameter if those refer to UNDEF symbols, which is not true if the
    symbol is in the same Compilation Unit as the caller of the function.
    """
    undef_sym = lief.ELF.Symbol()
    undef_sym.name = "__wrap_" + name
    undef_sym.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
    undef_sym.type = lief.ELF.SYMBOL_TYPES.FUNC
    undef_sym.shndx = lief.ELF.SYMBOL_SECTION_INDEX.UNDEF
    return undef_sym
    
def add_real_symbol(obj, symbol):
    """
    for the compilation unit where the "to be wrapped" function is defined we need to create a symbol with the name
    __real_XX so that the wrapper function (__wrap_XX) can call the real implementation via a call to real_XX.
    Only create the symbol if it is not already available in this CU, otherwise multiple defined linker errors will occur
    """
    for sym in obj.symbols:
        if sym.name == '__real_' + symbol.name:
            return
        
    real_sym = lief.ELF.Symbol()
    real_sym.name = "__real_" + symbol.name
    real_sym.binding = symbol.binding
    real_sym.exported = symbol.exported
    real_sym.imported = symbol.imported
    real_sym.information = symbol.information
    real_sym.other = symbol.other
    real_sym.shndx = symbol.shndx
    real_sym.size = symbol.size
    real_sym.type = symbol.type
    real_sym.value = symbol.value
    real_sym.visibility = symbol.visibility
    obj.add_static_symbol(real_sym)


def fix_symbols(obj, obj_file_name, fname):
    for idx, sym in enumerate(obj.symbols):
        if not sym.name.strip():
            continue
        if sym.name == fname:
            if sym.shndx != lief.ELF.SYMBOL_SECTION_INDEX.UNDEF:
                add_real_symbol(obj, sym)
            else:
                sym.name = "__wrap_" + fname
        
def fix_relocations(obj, obj_file_name, fname):
    """
    
    """
    for idx, reloc in enumerate(obj.relocations):
        logging.debug(f"{idx}/{len(obj.relocations)}")
        if not reloc.symbol.name.strip():
            continue
        logging.debug(f"{reloc.symbol.name} -> {fname}")
        if reloc.symbol.name == fname:
            logging.debug(f"Found {fname} in {obj_file_name}")
            if reloc.symbol.shndx != lief.ELF.SYMBOL_SECTION_INDEX.UNDEF:
                logging.debug(f"{fname} is defined in {obj_file_name}")
                add_real_symbol(obj, reloc.symbol)
                reloc.symbol = file_obj.add_static_symbol(make_undef_wrap_symbol(fname))
            else:
                logging.debug(f"{fname} is not defined in {obj_file_name}")
                reloc.symbol.name = "__wrap_" + reloc.symbol.name
                        
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dynamic Function Wrapping for Enhanced Debugging", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", "--config_file", required=False,
                        help="path to the config file containing the to wrapped function with the corresponding names",
                        default='')
    parser.add_argument("-w", "--wrap", required=False,
                        help="functions to wrap, any invocation of the functions with '-w FOO' will be replaced by calls to __wrap_FOO",
                        action='append', type=str)
    parser.add_argument("object_files", nargs='+',
                        help="file(s) containing the application in the relocatable object file")
    parser.add_argument("-v", "--version",
                        help="print the tool version and exit")

    if '-v' in sys.argv:
        print("{} {}".format(os.path.splitext(os.path.basename(sys.argv[0]))[0], script_version))
        sys.exit(0)

    args = parser.parse_args()
        
    if args.config_file != '':
        if not os.path.isfile(args.config_file):
            logging.error(f"Can't find {args.config_file}. Exiting")
            sys.exit(1)
        with open(args.config_file) as cfile:
            for line in cfile.readlines():
                sline = line.strip()
                if sline:
                    args.wrap.append(sline)
                
    if not args.wrap:
        logging.error("No wrapping functions provided. Exiting")
        sys.exit(1)

    args.wrap = list(set(args.wrap))
    for obj_file in args.object_files:
        if not os.path.isfile(obj_file):
            logging.warning(f"Can't find {obj_file} ... skipping")
            continue
        logging.debug(f"Processing {obj_file} ...")
        file_obj = lief.parse(obj_file)
        for wrap_func in args.wrap:
            logging.debug(f"Processing {wrap_func} in {obj_file} ...")
            fix_symbols(file_obj, obj_file, wrap_func)
            fix_relocations(file_obj, obj_file, wrap_func)
                        
        file_obj.write(obj_file)

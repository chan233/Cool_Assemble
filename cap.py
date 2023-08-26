from  capstone import *
# 通过capstone 写一个 arm32位下，thumb指令的反汇编函数
def disasm_arm(code, addr, count):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for i in range(count):
        print(md.disasm(code[i], addr + i * 2).mnemonic, end=" ")
        print(md.disasm(code[i], addr + i * 2).op_str)  


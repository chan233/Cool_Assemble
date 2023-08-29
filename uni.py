from  unicorn import *
from  capstone import *
import struct
'''
push {r4, r5, r7, lr}
mov r4, r1
ldrb r1, [r1]
cbz r1, #0x66
# blx #0x1f418

'''


CODE = b'\xB0\xB5\x0C\x46\x09\x78\x71\xB3\x05\x46\x0b\x46'
# \x1F\xF0'
#\x06\xEA'

def dis(CODE):
    print("=========asmCode===========")
    cs = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for i in cs.disasm(CODE,0,len(CODE)):
        print("%s  %s"%(i.mnemonic,i.op_str))

def readArm32Reg(mu):
    print("=======readArm32Reg==========")
    for i in range(arm_const.UC_ARM_REG_R0,arm_const.UC_ARM_REG_R8+1):
        print("R%d : %s" %(i-66,mu.reg_read(i)))






# typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);
def hookintr(uc,intno,user_data):

    print("===========hookintr===========")
    pass
# typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);
def hookinsn(uc,address,size,user_data):
    print("===========hookinsn===========")
    pass
# typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size,void *user_data);
def hookcode(uc,address,size,user_data):
    print("===========hookcode===========")
    dis(uc.mem_read(address,size))
    readArm32Reg(uc)
    pass

# typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,uint64_t address, int size, int64_t value,void *user_data);
def hookmem(uc,type,address,size,value,user_data):
    print("===========hookmem===========")
  
    if type == UC_MEM_FETCH_UNMAPPED:
        print("UC_MEM_FETCH_UNMAPPED")
        print("address:%s size: %s value: %s"%(hex(address),size,value))
        uc.mem_map(0x1bd08c,0x1000)
        return False
    


def emulibc():
    libcso = None
    with open("lib/libc.so","rb") as libcfile:        
        libcso = libcfile.read()
 
    
    cs = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for i in cs.disasm(libcso[0x0006cc88:],0,25):
        print("address:%s,%s,%s"%(hex(i.address+0x0006cc88),i.mnemonic,i.op_str))

    CODE = libcso[0x0006cc88:0x0006ccc4+3]
    # CODE = b'\x0a\x46\x35\x46'
    ADDRESS = 0x1000 # 必须是二的次方
    SIZE = 0x1000 # 必须是二的次方
    mu = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    mu.mem_map(address=ADDRESS,size=SIZE)
    
    mu.mem_write(ADDRESS,CODE)

    
    mu.hook_add(UC_HOOK_INTR,hookintr) # hook中断
    mu.hook_add(UC_HOOK_INSN,hookinsn)
    mu.hook_add(UC_HOOK_BLOCK,hookcode)
    mu.hook_add(UC_HOOK_CODE,hookcode)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED,hookmem)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED,hookmem)
    mu.hook_add(UC_HOOK_MEM_READ,hookmem)
    mu.hook_add(UC_HOOK_MEM_WRITE,hookmem)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED,hookmem)
    mu.reg_write(arm_const.UC_ARM_REG_R1,0x1);
    mu.reg_write(arm_const.UC_ARM_REG_R2,0x2);
    mu.reg_write(arm_const.UC_ARM_REG_R5,0x5);
    mu.reg_write(arm_const.UC_ARM_REG_R6,0x6);
    try:
        mu.emu_start(ADDRESS,ADDRESS+len(CODE))
    except UcError as e:
        print(e)   
    



emulibc()

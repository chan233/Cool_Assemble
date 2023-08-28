from  unicorn import *
from  capstone import *
'''
push {r4, r5, r7, lr}
mov r4, r1
ldrb r1, [r1]
cbz r1, #0x66
blx #0x1f418

'''


CODE = b'\xB0\xB5\x0C\x46\x09\x78\x71\xB3\x1F\xF0\x06\xEA'

def dis(CODE):
    print("=========dis========")
    cs = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for i in cs.disasm(CODE,0,len(CODE)):
        print("%s  %s"%(i.mnemonic,i.op_str))

def readArm32Reg(mu):
    print("=======readArm32Reg==========")
    for i in range(arm_const.UC_ARM_REG_R0,arm_const.UC_ARM_REG_R8):
        print("R%d : %s" %(i-66,mu.reg_read(i)))

def hook_code(mu,address,size,user_data):
    print("call hook_code")
    dis(mu.mem_read(address,size))
    readArm32Reg(mu)
    
  


def emu():
    um  = Uc(UC_ARCH_ARM,UC_MODE_THUMB)
    address = 0x1000
    size = 1024
    um.mem_map(address,size)
    um.mem_write(address,CODE)
    byte = um.mem_read(address,len(CODE))
  
    um.reg_write(arm_const.UC_ARM_REG_R1,0x100)

    # 在源码中 unicorn.h  中 找到 hook_code 回调的原型 
    # samplearm.c 中有使用方法
    # 注册回调要放在模拟器执行前 
    um.hook_add(UC_HOOK_CODE,hook_code)
    um.emu_start(address,address+4)

emu()
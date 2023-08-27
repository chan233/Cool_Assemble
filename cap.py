from  capstone import *
from keystone import *
'''
push {r4, r5, r7, lr}
mov r4, r1
ldrb r1, [r1]
cbz r1, #0x66
blx #0x1f418

'''


CODE = b'\xB0\xB5\x0C\x46\x09\x78\x71\xB3\x1F\xF0\x06\xEA'


def disam(code):
    cs = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    ks = Ks(KS_ARCH_ARM,KS_MODE_THUMB)
    for i in cs.disasm(code,0,len(code)):      
        
        print(i.mnemonic+" "+i.op_str)
        ins = ks.asm(i.mnemonic+" "+i.op_str)
        print("----------")
       
    



disam(CODE)
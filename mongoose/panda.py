import pandare, threading, socket
from struct import pack, unpack


''' this should be generic panda helpers ''' 

def p32(v): return pack('I',v)
def u32(b): return unpack('I',b)[0]
def wm(a,b): panda.virtual_memory_write(panda.get_cpu(),a,b)
def rm(a,s): return panda.virtual_memory_read(panda.get_cpu(),a,s)
def rs(a, sz=128): buf = rm(a, sz); return buf[:buf.index(b'\x00')]
def dr(a): return u32(rm(a,4))
def rr(r): return panda.arch.get_reg(panda.get_cpu(),r) if r != 'pc' else panda.arch.get_pc(panda.get_cpu())
def wr(r,v): panda.arch.set_reg(panda.get_cpu(),r,v) if r != 'pc' else panda.arch.set_pc(panda.get_cpu(),v)
def v2p(v): return panda.virt_to_phys(panda.get_cpu(), v)

saved_regs = []
def call(when, callback):
    global saved_regs
    if not saved_regs: saved_regs = {x:rr(x) for x in panda.arch.registers.keys()}

    addr = callback()

    if addr:
        # TODO: setup target call args

        wr('ra', when) # go back to the hook
        wr('pc', addr)

        return True

    for r,v in saved_regs.items(): wr(r,v)
    saved_regs = []
    return False

def serve():
    global sock
    s_sock = socket.socket()
    s_sock.setsockopt(1, 2, 1)
    s_sock.bind(('127.0.0.1',12345))
    s_sock.listen(1)
    print('listening')
    sock,_=s_sock.accept()
threading.Thread(target=serve,daemon=True).start()


''' and this is custom for our emulation ''' 

panda = pandare.Panda('mipsel', extra_args = ["-S","-s",'-singlestep',"-nographic","-machine","mipssim","-cpu","24Kf","-bios","/host/mongoose.rom","-device","loader,addr=0xbfc00400","-d","int,guest_errors"])


# FLAG "device"

flag = b'flag{YupThisIsTheFlag}'
@panda.hook_virt_mem_read(0xa2008000,0xa2008000+len(flag), True, False)
def vmbr(cpu, mad):
    panda.virtual_memory_write(cpu, mad.addr, flag[mad.addr-mad.hook.start_address:])


@panda.hook(0xbfc01100)
def write_display_data(cpu, tb, hook):
    wm(0xa2000008, b'\x02')
    print(chr(rr('a0')),end='')


BLOCK_COUNT=0
@panda.cb_before_block_exec
def insn(cpu, pc):
    global BLOCK_COUNT
    BLOCK_COUNT+=1
    if BLOCK_COUNT==2000:
        wm(0xa2100000, p32(dr(0xa2100000)+1))
        wm(0xa2100004, p32(dr(0xa2100000)+2))
        wm(0xa2100008, p32(dr(0xa2100000)+4))
        wm(0xa210000c, p32(dr(0xa2100000)+10))
        BLOCK_COUNT=0


TIMER=0
@panda.hook(0xbfc057f4)
def timer(cpu, tb, hook):
    global TIMER
    if TIMER%10==0: # yeah, that's a timer
        wm(0xa0180618, b'\x01')
    TIMER+=1


@panda.hook(0xbfc05940, cb_type='before_block_exec_invalidate_opt')
def write_interrupt(cpu, tb, hook):
    def uart_send(): 
        uart = dr(0xa0180580)
        wc = dr(uart+0x100c) #FIXME: I should not need this
        return 0xbfc046b4 if wc>0 else None

    return call(hook.addr, uart_send)

@panda.hook_virt_mem_write(0xa200001c,0xa2000020, False, True)
def vmwa(cpu, mad):
    sock.send(bytes(panda.ffi.buffer(mad.buf,mad.size))[::-1])

@panda.hook_virt_mem_write(0xa3000020,0xa3000024, False, True)
def output(cpu, mad):
    # print(bytes(panda.ffi.buffer(mad.buf,mad.size))[::-1])
    sock.send(rm(0xa3000024,0x10))


# hook when code checks the uart for data
@panda.hook(0xbfc05818, cb_type='before_block_exec_invalidate_opt')
def uart_has_data(cpu, tb, hook):

    def uart_recv():
        data = None
        uart = dr(0xa0180580)
        hd = dr(uart+0x1018) #FIXME: I should not need this
        if not hd:
            try:
                sock.settimeout(0.05)
                data = sock.recv(1)
                wm(0xa2000014, data) # endian things
            except socket.timeout: pass

        # run the uart recv interrupt if we have data - TODO: actually interrupt?
        return 0xbfc04490 if data else None

    return call(hook.addr, uart_recv)


panda.run()
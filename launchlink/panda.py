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
    sock.settimeout(0.05)
threading.Thread(target=serve,daemon=True).start()


''' and this is custom for our emulation ''' 

panda = pandare.Panda('mipsel', extra_args = ["-S","-s","-nographic","-machine","mipssim","-bios","/host/challenge.rom","-device","loader,addr=0xbfc00400","-d","int,guest_errors"])


# FLAG "device"

flag = b'flag{YupThisIsTheFlag}'
@panda.hook_virt_mem_read(0xa2008000,0xa2008000+len(flag), True, False)
def vmbr(cpu, mad):
    panda.virtual_memory_write(cpu, mad.addr, flag[mad.addr-mad.hook.start_address:])


# debug prints

@panda.hook(0xbfc04990)
def write_display_data(cpu, tb, hook):
    wm(0xa2000008, b'\x02')
    print(chr(rr('a0')),end='')


# UART

@panda.hook(0xbfc08d60, cb_type='before_block_exec_invalidate_opt')
def write_interrupt(cpu, tb, hook):

    def uart_send(): 
        uart = dr(0xa0180db0)
        wc = dr(uart+0x100c) #FIXME: I should not need this
        return 0xbfc08a98 if wc>=4 else None

    return call(hook.addr, uart_send)

@panda.hook_virt_mem_write(0xa200001c,0xa2000020, False, True)
def vmwa(cpu, mad):
    sock.send(bytes(panda.ffi.buffer(mad.buf,mad.size))[::-1])

# hook when code checks the uart for data
@panda.hook(0xbfc08d80, cb_type='before_block_exec_invalidate_opt')
def uart_has_data(cpu, tb, hook):

    def uart_recv():
        data = None
        try:
            data = sock.recv(4)
            wm(0xa2000014, data[::-1]) # endian things
        except socket.timeout: pass

        # run the uart recv interrupt if we have data - TODO: actually interrupt?
        return 0xbfc08960 if data else None

    return call(hook.addr, uart_recv)

panda.run()
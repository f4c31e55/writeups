import logging
import angr
from functools import partial

from angry_qemu import QEMU_Proxy

L = angr.SIM_LIBRARIES['linux']

logging.getLogger('angr.sim_procedure').setLevel(logging.DEBUG)
def f(*a,**k): return not any([m in a[0].getMessage() for m in ['next_tb','internal', 'syscall', 'CallReturn']])
logging.getLogger('angr.sim_procedure').addFilter(f)


class riscv_syscall(angr.SimProcedure):
    def run(self, env):
        s = self.state
        args = s.mem[env+(4*10)].uint32_t.array(8).resolved

        proc = L.procedures[L.syscall_number_mapping['riscv32'][args[-1].args[0]]]
        ret = proc.execute(self.state, arguments=[x.zero_extend(32) for x in args])

        s.mem[env+(4*10)].uint32_t = ret.ret_expr[31:]

        s.mem[env+0x80].uint32_t = s.mem[env+0x80].uint32_t.concrete+4

class mips_syscall(angr.SimProcedure):
    def run(self, env):
        s = self.state
        regs = s.mem[env].uint32_t.array(8).resolved
        regs = [r.zero_extend(32) for r in regs]
        sc = regs[2].args[0]
        args = regs[4:8]

        # oops, tried to fix a deliberate bug in the challenge ...
        # L.syscall_number_mapping['mips-o32'][6] = L.syscall_number_mapping['mips-o32'][4006]
        # have to fake out what qemu does for missing syscall
        if sc == 6:
            s.mem[env+4*2].uint32_t = 89 # E_NO_SYS
            s.mem[env+4*7].uint32_t = 1 # error flag
            s.mem[env+0x80].uint64_t = s.mem[env+0x80].uint64_t.concrete+4
            return
        elif sc == 4001: return self.exit(args[0])

        proc = L.procedures[L.syscall_number_mapping['mips-o32'][sc]]
        ret = proc.execute(self.state, arguments=args)

        if type(ret.ret_expr) == int:
            s.mem[env+4*2].uint32_t = ret.ret_expr
        else:
            s.mem[env+4*2].uint32_t = ret.ret_expr[31:]
        
        s.mem[env+0x80].uint64_t = s.mem[env+0x80].uint64_t.concrete+4

class arm_syscall(angr.SimProcedure):
    def run(self, env):
        s = self.state
        regs = s.mem[env].uint32_t.array(8).resolved
        regs = [r.zero_extend(32) for r in regs]
        sc = regs[7]
        args = regs[0:6]

        proc = L.procedures[L.syscall_number_mapping['arm'][sc.args[0]]]
        ret = proc.execute(self.state, arguments=args)

        if type(ret.ret_expr) == int:
            s.mem[env].uint32_t = ret.ret_expr
        else:
            s.mem[env].uint32_t = ret.ret_expr[31:]
    
class sparc_syscall(angr.SimProcedure):
    def run(self, env):
        s = self.state
        regs = s.mem[env].uint32_t.array(8).resolved
        regwptr = s.mem[env+0x90].uint64_t.resolved
        sc = regs[2].args[0]
        args = [x[31:].zero_extend(32) for x in s.mem[regwptr].uint64_t.array(4).resolved]

        proc = L.procedures[L.syscall_number_mapping['sparc'][sc]]
        ret = proc.execute(self.state, arguments=args)

        s.mem[regwptr].uint64_t = ret.ret_expr

        s.mem[env+0x80].uint64_t = s.mem[env+0x80].uint64_t.concrete+4


q = QEMU_Proxy([
    'gdbserver', '127.0.0.1:1235',
    './qemooo', '-d', 'nochain', './liccheck.bin'
])

t = q.target

p = angr.Project('./qemooo', main_opts={
    'base_addr': sorted([x.begin for x in t.avatar.memory_ranges if 'qemooo' in x.data.name])[0]},
)

p.hook(t.get_symbol('helper_raise_exception_riscv')[1], riscv_syscall())
p.hook(t.get_symbol('helper_raise_exception_sparc')[1], sparc_syscall())
p.hook(t.get_symbol('helper_exception_with_syndrome')[1], arm_syscall())
p.hook(t.get_symbol('helper_raise_exception_err')[1], mips_syscall())


@p.hook(q.base+0x16)
@p.hook(q.base+0x18)
def next_tb(state):
    ''' we hook at qemu's TB prologue and lift the new block to the angr state '''
    guest_pc = state.mem[state.regs.rbp+0x80].uint32_t.concrete
    tb = q.lift(guest_pc)
    state.regs.pc = tb.host_pc

state = p.factory.entry_state(addr=q.base+0x16)
state.posix.brk = (q.brk+0xfff)//0x1000*0x1000
state.regs.gs = 0 # qemu uses this as a base for guest maps

state.fs.insert(b'/lic',angr.SimFile('/lic', size=33, ident='lic'))
# state.fs.insert(b'/lic',angr.SimFile('/lic', content='04e7a3cb66233a6c0f4d513421d4a74e\n'))
state.fs.insert(b'/flag',angr.SimFile('/flag', size=36, ident='flag'))
# state.fs.insert(b'/flag',angr.SimFile('/flag', content=b"OOO{this is only a test flag, sorry}"))
with open('./games') as fp:
    state.fs.insert(b'/games',angr.SimFile('/games',content=fp.read()))


def do_you_even(s):
    ''' when angr tries to execute something new, we can return memory from the proxy '''
    addr = s.inspect.vex_lift_addr
    size = s.inspect.vex_lift_size
    q.mem.seek(addr-q.base)
    buff = q.mem.read(size)
    s.inspect.vex_lift_buff = buff
state.inspect.b('vex_lift',when=angr.BP_BEFORE,action=do_you_even, condition=lambda s:s.inspect.vex_lift_addr& 0xffff00000000 ==  q.base & 0xffff00000000)

state.regs.rbp = q.initial_ctx_addr
state.memory.store(state.regs.rbp, q.initial_ctx)
binary = t.rm(t.regs.gs_base+q.start_code,1,q.brk-q.start_code,raw=True)
state.memory.store(q.start_code, binary)
state.memory.store(t.regs.gs_base+q.start_code, binary)


def show_leak():
    ''' this function shows how the chall leaks data via the n command after a validation attempt '''
    
    s = state.copy()
    s.posix.stdin.content=[
        b'e',
        b'0'*32,
        b'v',
        b'n',
        b'p',
    ]
    simgr = p.factory.simgr(s)
    simgr.use_technique(angr.exploration_techniques.DFS())
    simgr.explore(find=lambda s:any([x.symbolic for x,y in s.posix.stdout.content]))
    assert simgr.found


def show_joshua():
    ''' this function shows how entering joshua will unlock the l command '''

    # this needs to be an ExplorationTechnique - the idea is to 'explore' between user inputs
    from num2words import num2words
    def conv(N, simgr):
        simgr.move('active', num2words(N+1), lambda s: len(s.posix.stdin.content) > N)
        simgr.drop(stash='deadended')
        return simgr

    s = state.copy()
    simgr = p.factory.simgr(s)
    INPS = len(state.posix.stdin.content)
    while simgr.active: simgr.run(step_func=partial(conv,INPS))

    INPS+=1
    simgr.move(num2words(INPS),'active')
    while simgr.active: simgr.run(step_func=partial(conv,INPS))
    options1 = set([s.posix.stdin.concretize()[0] for s in simgr.two])

    s = state.copy()
    s.posix.stdin.content=[
        b'j',
        b'oshua\n',
    ]
    simgr = p.factory.simgr(s)
    INPS = len(s.posix.stdin.content)
    while simgr.active: simgr.run(step_func=partial(conv,INPS))

    INPS+=1
    simgr.move(num2words(INPS),'active')
    while simgr.active: simgr.run(step_func=partial(conv,INPS))
    options2 = set([s.posix.stdin.concretize()[2] for s in simgr.four])

    assert options1 == {b'r', b'n', b'j', b'p', b'e'}
    assert options2 == {b'r', b'l', b'n', b'j', b'p', b'e'}


show_leak()
show_joshua()

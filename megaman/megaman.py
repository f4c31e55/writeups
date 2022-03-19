import angr, logging

from angry_qemu import ARM_QEMU_Proxy


L = angr.SIM_LIBRARIES['linux']

log = logging.getLogger('megaman'); log.setLevel(logging.INFO)


angr.sim_type.register_types(angr.sim_type.parse_type('''
   struct CPUARMState {
       uint32_t regs[16];
       uint64_t xregs[32];
       uint64_t pc;
       uint32_t pstate;
       uint32_t aarch64;
       uint32_t uncached_cpsr;
       uint32_t spsr;
       uint64_t banked_spsr[8];
       uint32_t banked_r13[8];
       uint32_t banked_r14[8];
       uint32_t usr_regs[5];
       uint32_t fiq_regs[5];
       uint32_t CF;
       uint32_t VF;
       uint32_t NF;
       uint32_t ZF;
       uint32_t QF;
       uint32_t GE;
       uint32_t thumb;
       uint32_t condexec_bits;
       uint64_t daif;
       uint64_t elr_el[4];
       uint64_t sp_el[4];
   }
   '''))

q = ARM_QEMU_Proxy([
    'gdbserver', '127.0.0.1:1235', 
    'qemu-arm','-singlestep','megaman'
])

t = q.target

p = angr.Project('qemu-arm', main_opts={
    'base_addr': sorted([x.begin for x in t.avatar.memory_ranges if 'qemu-arm' in x.data.name])[0]},
)

def flush_code(s):
    log.info('Flushing code section')
    code = s.solver.eval(s.memory.load(q.start_code,q.end_code-q.start_code),cast_to=bytes)
    t.wm(t.regs.gs_base+q.start_code,len(code),code,raw=True)
    with open('latest.mem','wb') as fp: fp.write(code) # ghidra_sync


GUEST_HOOKS = {0xb74:flush_code}
def guest_hook(addr, skip=0):
    def decorator(f):
        GUEST_HOOKS[addr] = f
    return decorator

@p.hook(q.base+0x16)
def next_tb(state):
    env = state.mem[state.regs.r14].struct.CPUARMState
    thumb = env.thumb.concrete
    ni = env.regs[15].concrete

    if ni-q.entry+0x254 in GUEST_HOOKS:
        GUEST_HOOKS[ni-q.entry+0x254](state)
        ni = env.regs[15].concrete

    tb = q.lift(ni, thumb)
    state.regs.pc = tb.host_pc
    state.memory.store(tb.host_pc, tb.code)
    if log.isEnabledFor(logging.DEBUG): log.debug(f'guest_pc {tb.guest_pc:x}')


""" these loop hooks aren't necessary but without executing the loops here, it takes a VERY long time to run """

@guest_hook(0x470)
def loop(s):
    r = s.mem[s.regs.r14].uint32_t.array(16).concrete
    ng = s.mem[s.regs.r14+0x218].uint32_t.concrete&0x80000000

    while 2:
        if not ng:
            r[6] = r[4]^r[7]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            ng = r[6] >= 0x80000000
        
        if ng:
            uvar5 = r[4] ^ 0x47
            r[4] &= 0xffffffff
            ng = uvar5 >= 0x80000000
        
        if not ng:
            pbvar2 = r[7] - 0x48
            r[7] -= r[5] >> (r[4]&0xff)
            r[7] &= 0xffffffff
            r[9] = s.mem[r[7]-0x48].uint8_t.concrete
            uvar5 = r[9]^s.mem[pbvar2].uint8_t.concrete<<4
            uvar5 &= 0xffffffff

            ng=False
        
        if not ng:
            s.mem[r[6]-0x48].uint8_t = uvar5
            r[6] -= r[5]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            r[7] -= r[5]>>(r[4]&0xff)
            r[7] &= 0xffffffff
            r[9] = 0x32 - r[9]
            r[9] &= 0xffffffff
            ng = r[9] >= 0x80000000

        if not ng: break

    for i in range(15):
        s.mem[s.regs.r14+i*4].uint32_t = r[i]
    s.mem[s.regs.r14+15*4].uint32_t = r[15]+44

@guest_hook(0x780)
def loop2(s):
    r = s.mem[s.regs.r14].uint32_t.array(16).concrete
    ng = s.mem[s.regs.r14+0x218].uint32_t.concrete&0x80000000

    while 2:
        if not ng:
            r[6] = r[4]^r[3]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            ng = r[6] >= 0x80000000
        
        if ng:
            r[7] = r[4] ^ 0x59
            r[7] &= 0xffffffff
            ng = r[7] >= 0x80000000
        
        if not ng:
            pbvar2 = r[3] - 0x44
            r[3] -= r[5] >> (r[4]&0xff)
            r[3] &= 0xffffffff
            r[8] = s.mem[r[3]-0x44].uint8_t.concrete
            r[7] = r[8]^s.mem[pbvar2].uint8_t.concrete<<4
            r[7] &= 0xffffffff

            ng=False
        
        if not ng:
            s.mem[r[6]-0x44].uint8_t = r[7]
            r[6] -= r[5]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            r[3] -= r[5]>>(r[4]&0xff)
            r[3] &= 0xffffffff
            r[8] = 0x32 - r[8]
            r[8] &= 0xffffffff
            ng = r[8] >= 0x80000000

        if not ng: break

    for i in range(15):
        s.mem[s.regs.r14+i*4].uint32_t = r[i]
    s.mem[s.regs.r14+15*4].uint32_t = r[15]+44

@guest_hook(0xa1c)
def loop3(s):
    r = s.mem[s.regs.r14].uint32_t.array(16).concrete
    ng = s.mem[s.regs.r14+0x218].uint32_t.concrete&0x80000000

    while 2:
        if not ng:
            r[6] = r[4]^r[3]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            ng = r[6] >= 0x80000000
        
        if ng:
            r[7] = r[4] ^ 0x31
            r[7] &= 0xffffffff
            ng = r[7] >= 0x80000000
        
        if not ng:
            pbvar2 = r[3] - 0x32
            r[3] -= r[5] >> (r[4]&0xff)
            r[3] &= 0xffffffff
            r[8] = s.mem[r[3]-0x32].uint8_t.concrete
            r[7] = r[8]^s.mem[pbvar2].uint8_t.concrete<<4
            r[7] &= 0xffffffff

            ng=False
        
        if not ng:
            s.mem[r[6]-0x32].uint8_t = r[7]
            r[6] -= r[5]>>(r[4]&0xff)
            r[6] &= 0xffffffff
            r[3] -= r[5]>>(r[4]&0xff)
            r[3] &= 0xffffffff
            r[8] = 0x32 - r[8]
            r[8] &= 0xffffffff
            ng = r[8] >= 0x80000000

        if not ng: break

    for i in range(15):
        s.mem[s.regs.r14+i*4].uint32_t = r[i]
    s.mem[s.regs.r14+15*4].uint32_t = r[15]+44

@guest_hook(0xac4)
def kernel_read(s):
    # slight hack ... 
    env = state.mem[state.regs.r14].struct.CPUARMState
    env.regs[0] = 0
    env.regs[15] = env.regs[15].concrete + 4


SIG={5:{},11:{}}
class HexagonSyscall(angr.SimProcedure):
    def run(self, env, excp, syndrome, target_el):
        s = self.state
        env = s.mem[s.regs.r14].struct.CPUARMState
        
        pc = env.regs[15].concrete
        if env.thumb.concrete: n = s.mem[pc-2].uint16_t.concrete&0xff
        else: n = s.mem[pc-4].uint32_t.concrete&0xffffff
        
        if n == 0x9f0002: # ARM_NR_cacheflush
            return flush_code(s)

        regs = env.regs.resolved
        args = [r.zero_extend(32) for r in regs]
        syscallnum = regs[7].args[0]

        if syscallnum == 0xf0001: 
            return handle_signal(s, 5)

        name = L.syscall_number_mapping['arm'][syscallnum]

        if name not in ['exit','read','write','close','mmap','mmap2','rt_sigaction','rt_sigreturn']: 
            env.regs[0] = -38 # ENOSYS
            return

        if name in ['exit','exit_group']: return self.exit(args[0])

        elif name == 'rt_sigaction': 
            action = s.mem[regs[1]].uint32_t.array(5).resolved
            SIG[regs[0].args[0]]['pc'] = action[0]
            SIG[regs[0].args[0]]['lr'] = action[2]

        elif name == 'rt_sigreturn':
            saved = s.mem[regs[13]+160].uint32_t.array(16+1).resolved
            for i in range(16):
                env.regs[i] = saved[i]
            env.thumb = saved[16]
            return

        proc = L.procedures[name]

        log.info(f"{proc.display_name}{args[:proc.num_args]} ... ")
        ret = proc.execute(s, arguments=args)
        
        if type(ret.ret_expr) == int:
            env.regs[0] = ret.ret_expr
        else:
            env.regs[0] = ret.ret_expr[31:]

        log.info(f"... {env.regs[0].resolved}")

class InternalException(angr.SimProcedure):
    def run(self, env, excp):
        if excp.args[0] == 9: # EXCP_KERNEL_TRAP
            s = self.state
            env = s.mem[s.regs.r14].struct.CPUARMState

            if env.regs[15].concrete == 0xffff0f60: #__kernel_cmpxchg64
                # TODO actually implement rather than assuming failure
                env.regs[15] = env.regs[14].resolved # blr
                handle_signal(s, 11)

            else:
                raise Exception(f'unhandled kernel jump {env.regs[15]}')

        else:
            raise Exception(f'unknown internal exception {excp}')

p.hook_symbol('helper_exception_with_syndrome', HexagonSyscall())
p.hook_symbol('helper_exception_internal', InternalException())

state = p.factory.entry_state(addr=q.base+0x16, remove_options={'COPY_STATES'})
state.memory.map_region(q.stack_limit,0x800000, 3, init_zero=True)
state.memory.store(q.start_code, t.rm(t.regs.gs_base+q.start_code,1,q.brk-q.start_code,raw=True))


def do_you_even(s):
    addr = s.inspect.vex_lift_addr
    size = s.inspect.vex_lift_size

    if log.isEnabledFor(logging.DEBUG): log.debug(f"Pulling {addr:x} {size:x}")
    if addr in q.h2g: 
        env = state.mem[state.regs.r14].struct.CPUARMState
        s.inspect.vex_lift_buff = q.lift(q.h2g[addr], env.thumb.concrete).code

def concretise(s):
    if s.inspect.address_concretization_result:
        log.info(f'address concretised ({s.mem[s.regs.r14].uint32_t.array(16)[15].resolved}) {s.inspect.address_concretization_expr} {[hex(x) for x in s.inspect.address_concretization_result]}')

state.inspect.b('vex_lift',when=angr.BP_BEFORE,action=do_you_even, condition=lambda s:s.inspect.vex_lift_addr and s.inspect.vex_lift_addr& 0xfffffff00000 ==  q.base & 0xfffffff00000)
state.inspect.b('address_concretization',when=angr.BP_AFTER,action=concretise)
def null_deref(): raise angr.SimSegfaultException(0, 'null deref')
state.inspect.b('mem_read',when=angr.BP_BEFORE,mem_read_address=0, action=lambda s: null_deref())


state.regs.rbp = t.regs.rbp
state.regs.gs = 0

state.regs.r14 = q.initial_ctx_addr
state.mem[state.regs.r14-0x1c].uint32_t = 1
state.memory.store(state.regs.r14, q.initial_ctx)

sp = state.mem[state.regs.r14].struct.CPUARMState.regs[13].concrete
state.memory.store(sp, t.rm(t.regs.gs_base+sp,1,q.stack_limit+0x800000-sp,raw=True))

simgr=p.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.DFS())

def handle_signal(s, signal):
    env = s.mem[s.regs.r14].struct.CPUARMState
    log.info(f"handle_signal {signal} {env.regs[15].resolved} {env.thumb}")

    regs = s.mem[s.regs.r14].uint32_t.array(16).resolved
    if signal == 5: env.regs[15] = env.regs[15].resolved - 4 # TODO: thumb
    
    sp = env.regs[13].resolved

    # setup sigcontext
    sf = sp-880
    sc = sf+160
    for i in range(16): s.mem[sc+i*4].uint32_t = env.regs[i].resolved
    s.mem[sc+16*4].uint32_t = env.thumb.resolved #huge hack
    s.mem[sc+224].uint32_t = env.uncached_cpsr.resolved

    # setup return
    env.regs[0] = signal
    env.regs[13] = sf
    env.regs[14] = SIG[signal]['lr']
    env.regs[15] = SIG[signal]['pc']
    env.thumb = 0 #TODO: this should come from the handler

    env.regs[1] = sf
    env.regs[2] = sf+128
    
    s.regs.pc = q.base+0x16


while simgr.active:
    simgr.step()
    for e in simgr.errored:
        if isinstance(e.error, angr.SimSegfaultException) and e.error.addr==0:
            handle_signal(e.state, 11)
            simgr.active.append(e.state)
            simgr.errored.remove(e)
        else: simgr.move('active','deferred')

s = simgr.errored[0].state
log.info(s.solver.eval(s.posix.stdin.content[0][0],cast_to=bytes)[:4])
assert s.solver.eval(s.posix.stdin.content[0][0],cast_to=bytes)[:4] == b'\x7fELF'
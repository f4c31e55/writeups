import angr, logging

from angry_qemu import Hexagon_QEMU_Proxy

log = logging.getLogger('hexagon'); log.setLevel(logging.INFO)


q = Hexagon_QEMU_Proxy([
    'gdbserver', '127.0.0.1:1235', 
    'qemu-hexagon','./hexagon'
])

t = q.target

p = angr.Project('qemu-hexagon', main_opts={
    'base_addr': sorted([x.begin for x in t.avatar.memory_ranges if 'hexagon' in x.data.name])[0],
})

@p.hook(q.base+0x16)
@p.hook(q.base+0x18)
def next_tb(state):
    guest_pc = state.mem[state.regs.rbp].uint32_t.array(64).concrete[41]
    log.info(f"guest_pc 0x{guest_pc:x}")

    tb = q.lift(guest_pc)
    state.regs.pc = tb.host_pc
    state.memory.store(tb.host_pc, tb.code) # looks like this if for fptrs in the code block

p.hook(t.get_symbol('lock_user')[1], angr.SIM_PROCEDURES['stubs']['Nop']())
p.hook(t.get_symbol('unlock_user')[1], angr.SIM_PROCEDURES['stubs']['Nop']())


class HexagonSyscall(angr.SimProcedure):
    def run(self, env):
        sys_table = {202: "accept",242: "accept4",89: "acct",217: "add_key",171: "adjtimex",200: "bind",280: "bpf",214: "brk",90: "capget",91: "capset",49: "chdir",51: "chroot",266: "clock_adjtime",405: "clock_adjtime64",114: "clock_getres",406: "clock_getres_time64",113: "clock_gettime",403: "clock_gettime64",115: "clock_nanosleep",407: "clock_nanosleep_time64",112: "clock_settime",404: "clock_settime64",220: "clone",57: "close",436: "close_range",203: "connect",285: "copy_file_range",106: "delete_module",23: "dup",24: "dup3",20: "epoll_create1",21: "epoll_ctl",22: "epoll_pwait",441: "epoll_pwait2",19: "eventfd2",221: "execve",281: "execveat",93: "exit",94: "exit_group",48: "faccessat",439: "faccessat2",223: "fadvise64_64",47: "fallocate",262: "fanotify_init",263: "fanotify_mark",50: "fchdir",52: "fchmod",53: "fchmodat",55: "fchown",54: "fchownat",25: "fcntl64",83: "fdatasync",10: "fgetxattr",273: "finit_module",13: "flistxattr",32: "flock",16: "fremovexattr",431: "fsconfig",7: "fsetxattr",432: "fsmount",430: "fsopen",433: "fspick",80: "fstat64",79: "fstatat64",44: "fstatfs64",82: "fsync",46: "ftruncate64",98: "futex",422: "futex_time64",236: "get_mempolicy",100: "get_robust_list",168: "getcpu",17: "getcwd",61: "getdents64",177: "getegid",175: "geteuid",176: "getgid",158: "getgroups",102: "getitimer",205: "getpeername",155: "getpgid",172: "getpid",173: "getppid",141: "getpriority",278: "getrandom",150: "getresgid",148: "getresuid",163: "getrlimit",165: "getrusage",156: "getsid",204: "getsockname",209: "getsockopt",178: "gettid",169: "gettimeofday",174: "getuid",8: "getxattr",105: "init_module",27: "inotify_add_watch",26: "inotify_init1",28: "inotify_rm_watch",3: "io_cancel",1: "io_destroy",4: "io_getevents",292: "io_pgetevents",416: "io_pgetevents_time64",0: "io_setup",2: "io_submit",426: "io_uring_enter",427: "io_uring_register",425: "io_uring_setup",29: "ioctl",31: "ioprio_get",30: "ioprio_set",272: "kcmp",294: "kexec_file_load",104: "kexec_load",219: "keyctl",129: "kill",445: "landlock_add_rule",444: "landlock_create_ruleset",446: "landlock_restrict_self",9: "lgetxattr",37: "linkat",201: "listen",11: "listxattr",12: "llistxattr",18: "lookup_dcookie",15: "lremovexattr",6: "lsetxattr",233: "madvise",235: "mbind",283: "membarrier",279: "memfd_create",238: "migrate_pages",232: "mincore",34: "mkdirat",33: "mknodat",228: "mlock",284: "mlock2",230: "mlockall",222: "mmap2",40: "mount",442: "mount_setattr",429: "move_mount",239: "move_pages",226: "mprotect",185: "mq_getsetattr",184: "mq_notify",180: "mq_open",183: "mq_timedreceive",419: "mq_timedreceive_time64",182: "mq_timedsend",418: "mq_timedsend_time64",181: "mq_unlink",216: "mremap",187: "msgctl",186: "msgget",188: "msgrcv",189: "msgsnd",227: "msync",229: "munlock",231: "munlockall",215: "munmap",264: "name_to_handle_at",101: "nanosleep",42: "nfsservctl",265: "open_by_handle_at",428: "open_tree",56: "openat",437: "openat2",241: "perf_event_open",92: "personality",438: "pidfd_getfd",434: "pidfd_open",424: "pidfd_send_signal",59: "pipe2",41: "pivot_root",289: "pkey_alloc",290: "pkey_free",288: "pkey_mprotect",73: "ppoll",414: "ppoll_time64",167: "prctl",67: "pread64",69: "preadv",286: "preadv2",261: "prlimit64",440: "process_madvise",270: "process_vm_readv",271: "process_vm_writev",72: "pselect6",413: "pselect6_time64",117: "ptrace",68: "pwrite64",70: "pwritev",287: "pwritev2",60: "quotactl",443: "quotactl_fd",63: "read",213: "readahead",78: "readlinkat",65: "readv",142: "reboot",207: "recvfrom",243: "recvmmsg",417: "recvmmsg_time64",212: "recvmsg",234: "remap_file_pages",14: "removexattr",38: "renameat",276: "renameat2",218: "request_key",128: "restart_syscall",293: "rseq",134: "rt_sigaction",136: "rt_sigpending",135: "rt_sigprocmask",138: "rt_sigqueueinfo",139: "rt_sigreturn",133: "rt_sigsuspend",137: "rt_sigtimedwait",421: "rt_sigtimedwait_time64",240: "rt_tgsigqueueinfo",125: "sched_get_priority_max",126: "sched_get_priority_min",123: "sched_getaffinity",275: "sched_getattr",121: "sched_getparam",120: "sched_getscheduler",127: "sched_rr_get_interval",423: "sched_rr_get_interval_time64",122: "sched_setaffinity",274: "sched_setattr",118: "sched_setparam",119: "sched_setscheduler",124: "sched_yield",277: "seccomp",191: "semctl",190: "semget",193: "semop",192: "semtimedop",420: "semtimedop_time64",71: "sendfile64",269: "sendmmsg",211: "sendmsg",206: "sendto",237: "set_mempolicy",99: "set_robust_list",96: "set_tid_address",162: "setdomainname",152: "setfsgid",151: "setfsuid",144: "setgid",159: "setgroups",161: "sethostname",103: "setitimer",268: "setns",154: "setpgid",140: "setpriority",143: "setregid",149: "setresgid",147: "setresuid",145: "setreuid",164: "setrlimit",157: "setsid",208: "setsockopt",170: "settimeofday",146: "setuid",5: "setxattr",196: "shmat",195: "shmctl",197: "shmdt",194: "shmget",210: "shutdown",132: "sigaltstack",74: "signalfd4",198: "socket",199: "socketpair",76: "splice",43: "statfs64",291: "statx",225: "swapoff",224: "swapon",36: "symlinkat",81: "sync",84: "sync_file_range",267: "syncfs",179: "sysinfo",116: "syslog",77: "tee",131: "tgkill",107: "timer_create",111: "timer_delete",109: "timer_getoverrun",108: "timer_gettime",408: "timer_gettime64",110: "timer_settime",409: "timer_settime64",85: "timerfd_create",87: "timerfd_gettime",410: "timerfd_gettime64",86: "timerfd_settime",411: "timerfd_settime64",153: "times",130: "tkill",45: "truncate64",166: "umask",39: "umount2",160: "uname",35: "unlinkat",97: "unshare",282: "userfaultfd",88: "utimensat",412: "utimensat_time64",58: "vhangup",75: "vmsplice",260: "wait4",95: "waitid",64: "write",66: "writev"}
        
        s = self.state
        regs = s.mem[env].uint32_t.array(8).resolved
        args = [r.zero_extend(32) for r in regs]
        syscallnum = regs[6].args[0]

        if sys_table[syscallnum] == 'exit_group': return self.exit(args[0])

        proc = angr.SIM_LIBRARIES['linux'].procedures[sys_table[syscallnum]]
        ret = proc.execute(s, arguments=args)
        log.info(f"{proc.display_name}{args[:proc.num_args]} {ret.ret_expr}")

        if type(ret.ret_expr) == int:
            s.mem[env].uint32_t = ret.ret_expr
        else:
            s.mem[env].uint32_t = ret.ret_expr[31:]

        s.mem[env+(4*41)].uint32_t = s.mem[env+(4*41)].uint32_t.resolved+4

p.hook(t.get_symbol('helper_J2_trap0')[1], HexagonSyscall())

state = p.factory.entry_state(addr=q.base+0x18)

state.memory.store(q.start_code, t.rm(q.start_code,1,q.brk-q.start_code,raw=True))


def do_you_even(s):
    addr = s.inspect.vex_lift_addr
    size = s.inspect.vex_lift_size
    q.mem.seek(addr-q.base)
    buff = q.mem.read(size)
    s.inspect.vex_lift_buff = buff

state.inspect.b('vex_lift',when=angr.BP_BEFORE,action=do_you_even, condition=lambda s:s.inspect.vex_lift_addr& 0xffff00000000 ==  q.base & 0xffff00000000)

state.regs.rbp = t.regs.rbp
state.mem[t.regs.rbp-8].uint32_t = 1
state.memory.store(t.regs.rbp, q.initial_ctx)


def test(state):
    simgr=p.factory.simgr(state)
    simgr.run()
    for s in simgr.deadended:
        print(' INPUT:',s.posix.dumps(0), '\nOUTPUT:', s.posix.dumps(1),'\n')
    for s in simgr.deadended:
        if b'IDigVLIW' in s.posix.dumps(0): return True
    return False

assert test(state)

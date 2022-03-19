# megaman

[challenge tweet](https://twitter.com/ebeip90/status/1422428930791854080)

## description

megaman is a reverse engineering challenge that is resistant to both static and dynamic analysis. There are probably several sensible ways to approach this; I chose none of those. I had previously written a tool to use angr and qemu to analyse binaries [angry_qemu](https://github.com/f4c31e55/angry_qemu) and thought I'd roll it out for this as well, assuming instrumenting qemu would be easier than dealing with the binary (spoiler: it was) and then angr could deal with any exploration I might need (spoiler: didn't need this ... oof).

There were lots of interesting bits and pieces the binary did and I had to add some code into angry_qemu I'd not thought about before. I enjoyed diving into qemu internals so shoutout to Zach for putting up the challenge.

## the issues

### obfuscation
The code is obfuscated and ASCII encoded. Given we're doing dynamic analysis, this doesn't really affect us. We can dump the deobfuscated code later if we want to look at it statically. There is a dynamically generated xor key used to decode instructions, which we obviously have to get correct, and various pieces of our harnessing need to mirror qemu's environment so that we have the correct key created. I'll refer back to this as required.

### custom qemu
The challenge comes with a patch to qemu which largely just removes all syscalls, except `exit,read,write,close,mmap,mmap2,rt_sigaction,rt_sigreturn`. This was pretty helpful for me as I only had to worry about a small set to hand off to angr and they were super simple ones.

The challenge needs to be run inside qemu. It pulls things from the qemu environment to add into the xor key for decoding the instructions. I'd not needed this before, so I added guest stack loading into angr, easy. 

### sigaction and sigreturn
The binary sets up its own signal handlers for SIG_SEGV and SIG_TRAP. It uses them for a simple form of control flow but it does make life harder for people trying to debug or fuzz. I mocked out a function to handle a signal; only partially implemented, but good enough for how it was being used. Then hooked this in the syscalls for sigaction and sigreturn, which angr doesn't have so, again, a cheap implementation to get it moving.

#### self modifying code
Parts of the code deobfuscate later instructions, usually via xoring the memory. Fortunately it won't overwrite an instuction it's already executed so all we need to do is forward the memory writes on to qemu so that later `tb_find`s will see the correct instruction data. We could do this using an angr mem_write breakpoint for the code section but the code actually uses the syscall interface with `swipl      0x9f0002` (`ARM_NR_cacheflush`) to flush the cache. qemu doesn't do anything with it but we can use it as a signal to update qemu's idea of the code from angr's. There's one additional place we call `flush_cache`, I'm not sure whether the challenge missed one and it wouldn't work on real hardware or whether the flush is triggered by something else. 

I added the code for ARM_NR_cacheflush and ARM_NR_breakpoint to the syscall handler.

### weird address reads
The binary will read from address 0 as we can see in angr's output.
```
WARNING | 2021-08-22 14:43:19,520 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x0 with 4 unconstrained bytes referenced from 0x55555581ff9f (static_code_gen_buffer+0x43ff in qemu-arm (0x2cbf9f))
```
angr has its own way to deal with incorrect memory accesses but I used a mem_read breakpoint to keep fine control over which bad addresses were being used.
```python
def null_deref(): raise angr.SimSegfaultException(0, 'null deref')
state.inspect.b('mem_read',when=angr.BP_BEFORE,mem_read_address=0, action=lambda s: null_deref())
```
The thrown exception is caught and punted to our code to handle signals.

The other address read from which gives us weird behaviour is 0xffff0f60. Need to dive into the qemu code for this one and it turns out it's a special kernel address that can be read from and even called. The call ends up being a `__kernel_cmpxchg64` but the addresses are bad so we can trigger a SIG_SEGV here and not worry too much. 

### file descriptors
The code does some weird things with file descriptors. Firstly it will write some data to fd 4, no idea where the data came from, but the write needs to fail as the result is added into the xor key. Then it will start closing fds from 2 until it fails, in all likelihood at 3. Again, these return values are added into the xor key. This is actually a bigger deal than it seems because qemu has some great debugging output with args like `-d cpu,exec`. These go to stderr so will cease to appear after the calls to close. There are some tricks to get past this but as we're instrumenting qemu, it doesn't matter. I changed some returns from angr's posix layer for close and write from -1 to -EBADF.

## the end
When we code around all the crazies, we see the code mmap'ing us some memory and then finally reading something into it. A chance for us to affect something. As we're using angr it'll execute on and explore for us. We get some cool output:
```
INFO    | 2022-03-13 12:59:26,352 | megaman | mmap2[<BV64 0x0>, <BV64 0x1000>, <BV64 0x3>, <BV64 0x22>, <BV64 0x0>, <BV64 0x0>] ... 
INFO    | 2022-03-13 12:59:26,356 | megaman | ... <BV32 0xc0080000>
INFO    | 2022-03-13 12:59:38,583 | megaman | address concretised (<BV32 0x4ca25c20>) <BV64 0#32 .. 0xc0080000 + (packet_0_stdin_44_32768[32519:32512] .. packet_0_stdin_44_32768[32527:32520] .. packet_0_stdin_44_32768[32535:32528] .. packet_0_stdin_44_32768[32543:32536])> ['0xff800000']
```
Which means angr mmap's us some memory and then built an address based off our input, which sounds pretty good. In symbolic terms this is called address conretisation because a symbolic pointer could well point to any address so we need to decide on a value for it. It then does some more address concretisation and we get:
```
INFO    | 2022-03-13 12:59:40,530 | megaman | mmap2[<BV64 0#32 .. (mem_ff800008_46_32{UNINITIALIZED}[31:12] .. 0x0)>, <BV64 0#32 .. (0x1 + mem_ff800014_47_32{UNINITIALIZED}[27:12] .. 0x0)>, <BV64 0x7>, <BV64 0x32>, <BV64 0x0>, <BV64 0x0>] ...
ERROR   | 2022-03-13 12:59:40,656 | angr.procedures.posix.mmap | Cannot handle symbolic addr argument for mmap.
```
This means we have even more control over the mmap than the previous one. Also it's allocating executable memory which ain't half bad. What we know is that we've sent some input and it's pulled values from various offsets and used them to start allocating memory addresses. If we ask angr how it got down this path it's easy to take a guess at what's going on:
```python
s = simgr.errored[0].state
s.solver.eval(s.posix.stdin.content[0][0],cast_to=bytes)[:4] == b'\x7fELF'
```
It's loading an ELF we send it. So after all this work, all we really had to do was send it an ELF ... and that's where the challenge begins!

## the solution
I'll leave this as an exercise for the reader, but suffice it to say, when you've dug through all the exception, interrupt and syscall handling code in qemu, it was obvious what the solution was and only took about five minutes to code up.

```
python3 mega.py
[+] Starting local process './qemu-arm': pid 810143
[+] Receiving all data: Done (29B)
[+] b'The_Goal_Is_To_Read_This_File'
```

## hindsight
angr has a wonderfully featured API and aside from all the benefit of symbolic execution, the inspect engine, which is effectively callbacks for different events, is so useful for dynamically analysing some code. As I mentioned earlier, a simple log line for address concretisation is a very fast way to understand that input data is being used as an offset into memory that was mmap'd. 

If I were to go back and do it again, I'd likely not bother using angry_qemu. It was fun increasing the fidelity to running directly in qemu but in this case was overkill. For a second shot at this, I think I would set a breakpoint as qemu was executing a TB and then dump the instruction and register context into a format compatible with ghidra's TraceDB. I've not used it before but I think this would fit nicely, dynamically building the deobfuscated binary back up and being able to time travel debug. I would miss out on angr being able to tell me the bytes I needed to send, but my guess is that we'd see the comparison to `\x7fELF` and that would have been enough.

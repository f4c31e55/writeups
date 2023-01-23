# mongoose

This was an exploitation challenge, part of HackASat quals 2021.

[challenge](https://github.com/cromulencellc/hackasat-qualifier-2021/tree/main/mongoose)

[writeup](https://github.com/cscosu/ctf-writeups/tree/master/2021/hack_a_sat/mongoose_mayhem)

## mongoose.py
The solution script shows how the eagle<->lion interaction of sphynx can be useful. Or in real words: sometime's it's useful to pull an angr state from a running target and symbolically execute it. 

The exploit here is trivial because so was the bug. There is functionality to store shellcode, modulo some floating point requirements, and also functionality to overwrite a return address. The shellcode exfils 16 bytes of the flag via the sensor device. 
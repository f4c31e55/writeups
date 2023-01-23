# launchlink

This was an exploitation challenge, part of HackASat quals 2020.

[challenge](https://github.com/cromulencellc/hackasat-qualifier-2020/tree/master/rfmagic)

[perfect blue writeup](http://blog.perfect.blue/Hack-A-Sat-CTF-2020-Launch-Link)

## launchlink.py
The solution script shows how the dragon<->lion interaction of sphynx can be useful. Or in real words: sometimes it's useful to make use of the target binary's code e.g. rather than reimplement the crc or crypt algorithms in python, let's just use ghidra's emulator to run the actual code. It's slower to run but much faster to implement than manually lifting MIPS to python. 

Two breakpoints remain in the script, yet unused. These were for turning on the debug prints from the firmware while developing and also pulling the initial crypt state so that the key exchange didn't need to be implemented. 

The exploit is overcomplicated due to not understanding/checking what the memory protections in vmips would be. 
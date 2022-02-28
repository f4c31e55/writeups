# hexagon

This was a reversing challenge, part of Google CTF 2021.

[challenge](https://capturetheflag.withgoogle.com/challenges/rev-hexagon)

## hexagon.py
This was likely intended as a static reverse engineering challenge to introduce the hexagon architecture, which had recently made it into qemu. Also, it was showing off Google's hexagon binary ninja plugin. 

Given the fact it executes, under qemu, on more common architectures, it's also possible to build a dynamic solution to this challenge using angr to execute the translation blocks from within qemu. It's even possible to use angr's classic example of `simgr.explore(find = lambda state: b'Congratulations' in state.posix.dumps(1))`
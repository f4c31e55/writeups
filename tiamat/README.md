# tiamat

This was a jeopardy challenge, part of dc2021q.

[ooo archive](https://archive.ooo/c/tiamat/401/)

[source (spoilers)](https://github.com/o-o-overflow/dc2021q-tiamat-public)

[more source (more spoilers)](https://github.com/o-o-overflow/qemooo)

[dttw writeup](https://dttw.tech/posts/HJ9TU7J_O)

## tiamat.py
tiamat was a tricky static reverse engineering problem. It was even harder to analyse dynamically. This script provides an option for dynamic exploration of the binary.

The included script provides a dynamic analysis base using angr with a qemu proxy to symbolically emulate the translation blocks. Simply put, as angr discovers the host code for guest instructions, it will pull the memory from qemu and execute the new block. The syscall handlers for each architecture tiamat uses are hooked to hand off to angr's syscall engine. 

Two pieces of functionality are shown in the script. One takes a set of inputs which causes the challenge to leak information to the user. Here we explore until there is symbolic content in stdout. The second explores the options for input. Here we explore between reads of stdin. This also shows how entering 'joshua' will increase the available options.
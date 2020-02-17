# pwnyracing_chall21

My solution for pwnyracing chall21.
The exploit can be run by executing exploit.sh

## requirements

1. python
2. pwntools
3. gdb
4. libc-database
5. gef recomended
6. pwngdb recomended

## The Executeable
The executeable asks for a input and simply outputs it back to you in a loop.

## Vulnerability
there is a simple stack buffer overflow error at address 0xb31 as we can copyes at most 200 bytes to a buffer of size 0x48

### checksec on ./chall21

* Arch:       amd64-64-little
* RELRO:   Full RELRO
* Stack:     Canary found
* NX:          NX enabled
* PIE:         PIE enabled

## Exploit idea

As there is a loop we can abuse the buffer overflow as many times as we want which will be very handy.

Attack idea:
1. Leak stack canary
2. Leak ELF base address
3. build small rop chain to leak printf addresses
4. make the rop chain run main again to exploit buffer overflow once more
5. send oneGadget with the now know libc version

### Leak stack canary
simply send 0xe49 A's as this will fill the buffer and the first null char of the stack canary
and now the printf of the buffer will print 0x49 A's followed by 7 bytes of stack canary and the first byte of a stack canary is always null.

### Leak ELF base address
As the program is compilled with pie the program could be loaded any where in memory and we need to create a rop chain, so we need to leak a code address.
As stack canarys protect the return addresses we can just use the buffer overflow to override the stack canary and get a pointer to the exitFunction
now substact the address of the exitFunction in the elf file from this address and we know where in memory the elf is loaded.

### build small rop chain to leak printf addresses
We fist build a simple rop chain leaking the libc printf address.
Besides constructing the simple rop chain we need the program to rerun after executing so first we need to make a stack pivot as we else would try to write to invalid memory next time we run the program.
We simply stack pivot to the bss sections as we have some read/write space there, and this address is know as we know the base address.
Furthere more we can't return directly to main as main clears what ever parameter was send as argv and envp.
So we instead return to main + a small offset to after the clearing of these two pointers are done.

Use the rop chain to leak the GOT pointer to printf to get a libc address, and do it for a couple of more functions.

now use libc-databsase to find the libc version used on the remote server (libc and ld for server is included in the repo):
```
./find printf 0xa7fd28dd69000 puts .....
```

### send oneGadget with the now know libc version
now we simply use one_gadget to test multiple one gadgets if they work on the remote and cross our fingers :-)
```
one_gadget "./libc.so.6" -s 'python exploit.py --gdbplugin pwndbg --ld ./ld-2.27.so --libc ./libc.so.6 --exec remote --host "challenge.pwny.racing" --port 40021 NOASLR'
```

This should pop a shell with the gadget at 0x4f2c5 + libc base
Remeber that we may need to run the exploit onec more if it don't work the first time as we can't input the newline char and that may be required to insert the stack canary.

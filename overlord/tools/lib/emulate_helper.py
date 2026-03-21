"""
Unicorn Engine emulator helper for emulate.ts
Usage: python3 emulate_helper.py '<json_payload>'
Payload: { binary, start, end, breakpoints, init_regs }
Output:  JSON { success, snapshots, error }
"""

import sys
import json
import os
import struct

def parse_elf(data: bytes):
    """Return list of (vaddr, file_offset, size) for LOAD segments."""
    if data[:4] != b'\x7fELF':
        return None, None
    ei_class = data[4]  # 1=32bit, 2=64bit
    ei_data  = data[5]  # 1=LE, 2=BE
    bits = 64 if ei_class == 2 else 32
    le   = ei_data == 1

    endian = '<' if le else '>'
    if bits == 64:
        e_phoff, = struct.unpack_from(endian + 'Q', data, 32)
        e_phentsize, = struct.unpack_from(endian + 'H', data, 54)
        e_phnum,     = struct.unpack_from(endian + 'H', data, 56)
    else:
        e_phoff, = struct.unpack_from(endian + 'I', data, 28)
        e_phentsize, = struct.unpack_from(endian + 'H', data, 42)
        e_phnum,     = struct.unpack_from(endian + 'H', data, 44)

    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if bits == 64:
            p_type,  = struct.unpack_from(endian + 'I', data, off)
            p_offset,= struct.unpack_from(endian + 'Q', data, off + 8)
            p_vaddr, = struct.unpack_from(endian + 'Q', data, off + 16)
            p_filesz,= struct.unpack_from(endian + 'Q', data, off + 32)
            p_memsz, = struct.unpack_from(endian + 'Q', data, off + 40)
        else:
            p_type,  = struct.unpack_from(endian + 'I', data, off)
            p_offset,= struct.unpack_from(endian + 'I', data, off + 4)
            p_vaddr, = struct.unpack_from(endian + 'I', data, off + 8)
            p_filesz,= struct.unpack_from(endian + 'I', data, off + 16)
            p_memsz, = struct.unpack_from(endian + 'I', data, off + 20)
        if p_type == 1:  # PT_LOAD
            segments.append((p_vaddr, p_offset, p_filesz, p_memsz))
    return segments, bits


def detect_arch(data: bytes):
    """Return (uc_arch, uc_mode) tuple."""
    try:
        from unicorn import UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64, UC_ARCH_MIPS
        from unicorn import UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN
        if data[:4] == b'\x7fELF':
            ei_class = data[4]
            e_machine, = struct.unpack_from('<H', data, 18)
            if e_machine in (62, 0x3e):   # x86-64
                return UC_ARCH_X86, UC_MODE_64
            if e_machine == 3:            # x86
                return UC_ARCH_X86, UC_MODE_32
            if e_machine == 183:          # AArch64
                return UC_ARCH_ARM64, UC_MODE_ARM
            if e_machine in (40, 0x28):   # ARM
                return UC_ARCH_ARM, UC_MODE_ARM
        # fallback x86-64
        return UC_ARCH_X86, UC_MODE_64
    except Exception:
        from unicorn import UC_ARCH_X86, UC_MODE_64
        return UC_ARCH_X86, UC_MODE_64


def reg_map_x86_64():
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
    )
    return {
        'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX,
        'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX,
        'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
        'rbp': UC_X86_REG_RBP, 'rsp': UC_X86_REG_RSP,
        'r8':  UC_X86_REG_R8,  'r9':  UC_X86_REG_R9,
        'r10': UC_X86_REG_R10, 'r11': UC_X86_REG_R11,
        'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13,
        'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15,
        'rip': UC_X86_REG_RIP, 'eflags': UC_X86_REG_EFLAGS,
    }


def reg_map_x86_32():
    from unicorn.x86_const import (
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
        UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
    )
    return {
        'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX,
        'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
        'esi': UC_X86_REG_ESI, 'edi': UC_X86_REG_EDI,
        'ebp': UC_X86_REG_EBP, 'esp': UC_X86_REG_ESP,
        'eip': UC_X86_REG_EIP, 'eflags': UC_X86_REG_EFLAGS,
    }


def read_all_regs(uc, rmap):
    return {name: hex(uc.reg_read(rid)) for name, rid in rmap.items()}


PAGE = 0x1000

def align_down(v): return v & ~(PAGE - 1)
def align_up(v):   return (v + PAGE - 1) & ~(PAGE - 1)


def emulate(payload: dict) -> dict:
    from unicorn import Uc, UC_PROT_ALL, UcError
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID

    binary_path = payload['binary']
    start       = int(payload['start'], 16)
    end         = int(payload['end'],   16)
    breakpoints = set(int(b, 16) for b in payload.get('breakpoints', []))
    init_regs   = payload.get('init_regs', {})

    with open(binary_path, 'rb') as f:
        data = f.read()

    segments, bits = parse_elf(data)
    arch, mode     = detect_arch(data)
    uc = Uc(arch, mode)

    # Choose register map
    from unicorn import UC_ARCH_X86
    if arch == UC_ARCH_X86:
        rmap = reg_map_x86_64() if mode != 32 else reg_map_x86_32()
        try:
            from unicorn import UC_MODE_32
            rmap = reg_map_x86_32() if mode == UC_MODE_32 else reg_map_x86_64()
        except Exception:
            rmap = reg_map_x86_64()
    else:
        rmap = {}

    if segments:
        for (vaddr, foff, filesz, memsz) in segments:
            base = align_down(vaddr)
            size = align_up(vaddr + memsz) - base
            if size == 0:
                continue
            try:
                uc.mem_map(base, size, UC_PROT_ALL)
            except UcError:
                pass  # already mapped or overlap
            chunk = data[foff: foff + filesz]
            try:
                uc.mem_write(vaddr, chunk)
            except UcError:
                pass
    else:
        # Flat binary: map entire file
        base = align_down(start)
        size = align_up(len(data) + base) - base
        uc.mem_map(base, max(size, PAGE), UC_PROT_ALL)
        uc.mem_write(base, data)

    # Stack
    STACK_BASE = 0x7fff_f000_0000
    STACK_SIZE = 0x10_0000
    try:
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        if rmap:
            sp_reg = rmap.get('rsp') or rmap.get('esp')
            if sp_reg:
                uc.reg_write(sp_reg, STACK_BASE + STACK_SIZE // 2)
    except UcError:
        pass

    # Apply init_regs
    for name, val in init_regs.items():
        rid = rmap.get(name.lower())
        if rid is not None:
            try:
                uc.reg_write(rid, int(val, 16) if isinstance(val, str) else int(val))
            except Exception:
                pass

    snapshots = []

    def hook_code(uc, address, size, user_data):
        if not breakpoints or address in breakpoints:
            regs = read_all_regs(uc, rmap) if rmap else {}
            snapshots.append({'address': hex(address), 'size': size, 'regs': regs})

    def hook_mem(uc, access, address, size, value, user_data):
        return False  # don't crash, just report

    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem)

    try:
        uc.emu_start(start, end, timeout=30_000_000)  # 30s in microseconds
    except UcError as e:
        return {
            'success': len(snapshots) > 0,
            'snapshots': snapshots,
            'error': str(e),
        }

    return {'success': True, 'snapshots': snapshots}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({'success': False, 'error': 'No payload argument'}))
        return

    try:
        payload = json.loads(sys.argv[1])
    except json.JSONDecodeError as e:
        print(json.dumps({'success': False, 'error': f'Invalid JSON payload: {e}'}))
        return

    try:
        result = emulate(payload)
    except Exception as e:
        result = {'success': False, 'snapshots': [], 'error': str(e)}

    print(json.dumps(result))


if __name__ == '__main__':
    main()

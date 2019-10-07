import re
import idaapi
import idc
import yara
import binascii
from capstone import *
from capstone.x86 import *
from unicorn import *
from unicorn.x86_const import *

rules = """
rule jumps_with_constant_condition
{
    meta:
        created = "02.07.2019"
        modified = "04.09.2019"
        author = "ArcherCreat"

    strings:
        $general_1 = {(50 | 51 | 52 | 53 | 57 | 83 [2] 89 ?? 24) 9C 8B ?? 24 [3] 89 ?? 24 9D}
        $general_2 = {(50 | 83 [2] 89 ?? 24) 9C 8B ?? 24 [5] 89 ?? 24 9D}
        $general_3 = {(51 | 52 | 53 | 57) 9C 8B ?? 24 [6] 89 ?? 24 9D}
        $general_4 = {(51 B9 | 52 BA | 53 BB | 57 BF | 83 [2] 89 ?? 24) [4] 81 ?? ?? ?? ?? ??}
        $general_5 = {(51 B9 | 52 BA | 53 BB | 57 BF | 83 [2] 89 ?? 24) [4-5] F7 C? ?? ?? ?? ??}
        $general_6 = {(50 B8 | 83 [2] 89 ?? 24 B8) [4] (05 | 2D | 3D | A9 | 0D | 25 | 15 | 35) ?? ?? ?? ??}

        $eax_1 = {50 B8 [4] (40 | 48)}
        $eax_2 = {50 B8 [4] F7 D8}

        $ecx_1 = {51 B9 [4] (41 | 49)}
        $ecx_2 = {51 B9 [4] F7 D9}

        $edx_1 = {52 BA [4] (42 | 4A)}
        $edx_2 = {52 BA [4] F7 DA}

        $ebx_1 = {53 BB [4] (43 | 4B)}
        $ebx_2 = {53 BB [4] F7 DB}

        $edi_1 = {57 BF [4] (47 | 4F)}
        $edi_2 = {57 BF [4] F7 DF}

        $sub_esp_1 = {83 [2] 89 ?? 24 B? [4] F7 ??}
        $sub_esp_2 = {83 [2] 89 ?? 24 B? [4] 4?}
        $sub_esp_3 = {83 [2] 89 ?? 24 9C 8B ?? 24 81 [5] 89 ?? 24 9D}
        $sub_esp_4 = {83 [2] 89 ?? 24 [5] 81 ?? ?? ?? ?? ??}

    condition:
        any of them
}

rule inderect_jumps
{
    meta:
        created = "03.07.2019"
        modified = "04.09.2019"
        author = "ArcherCreat"

    strings:
        $short_jumps_1 = {(70 | 71) ?? (71 | 70) ??}
        $short_jumps_2 = {(72 | 73) ?? (73 | 72) ??}
        $short_jumps_3 = {(74 | 75) ?? (75 | 74) ??}
        $short_jumps_4 = {(76 | 77) ?? (77 | 76) ??}
        $short_jumps_5 = {(78 | 79) ?? (79 | 78) ??}
        $short_jumps_6 = {(7A | 7B) ?? (7B | 7A) ??}
        $short_jumps_7 = {(7C | 7D) ?? (7D | 7C) ??}
        $short_jumps_8 = {(7E | 7F) ?? (7F | 7E) ??}

        $far_jumps_1 = {0F (80 | 81) ?? ?? ?? ?? 0F (81 | 80) ?? ?? ?? ??}
        $far_jumps_2 = {0F (82 | 83) ?? ?? ?? ?? 0F (83 | 82) ?? ?? ?? ??}
        $far_jumps_3 = {0F (84 | 85) ?? ?? ?? ?? 0F (85 | 84) ?? ?? ?? ??}
        $far_jumps_4 = {0F (86 | 87) ?? ?? ?? ?? 0F (87 | 86) ?? ?? ?? ??}
        $far_jumps_5 = {0F (88 | 89) ?? ?? ?? ?? 0F (89 | 88) ?? ?? ?? ??}
        $far_jumps_6 = {0F (8A | 8B) ?? ?? ?? ?? 0F (8B | 8A) ?? ?? ?? ??}
        $far_jumps_7 = {0F (8C | 8D) ?? ?? ?? ?? 0F (8D | 8C) ?? ?? ?? ??}
        $far_jumps_8 = {0F (8E | 8F) ?? ?? ?? ?? 0F (8F | 8E) ?? ?? ?? ??}

        $mix_1 = {0F (80 | 81) ?? ?? ?? ?? (71 | 70) ??}
        $mix_2 = {0F (82 | 83) ?? ?? ?? ?? (73 | 72) ??}
        $mix_3 = {0F (84 | 85) ?? ?? ?? ?? (75 | 74) ??}
        $mix_4 = {0F (86 | 87) ?? ?? ?? ?? (77 | 76) ??}
        $mix_5 = {0F (88 | 89) ?? ?? ?? ?? (79 | 78) ??}
        $mix_6 = {0F (8A | 8B) ?? ?? ?? ?? (7B | 7A) ??}
        $mix_7 = {0F (8C | 8D) ?? ?? ?? ?? (7D | 7C) ??}
        $mix_8 = {0F (8E | 8F) ?? ?? ?? ?? (7F | 7E) ??}
        $mix_9 = {(71 | 70) ?? 0F (80 | 81) ?? ?? ?? ??}
        $mix_A = {(73 | 72) ?? 0F (82 | 83) ?? ?? ?? ??}
        $mix_B = {(75 | 74) ?? 0F (84 | 85) ?? ?? ?? ??}
        $mix_C = {(77 | 76) ?? 0F (86 | 87) ?? ?? ?? ??}
        $mix_D = {(79 | 78) ?? 0F (88 | 89) ?? ?? ?? ??}
        $mix_E = {(7B | 7A) ?? 0F (8A | 8B) ?? ?? ?? ??}
        $mix_F = {(7D | 7C) ?? 0F (8C | 8D) ?? ?? ?? ??}
        $mix_0 = {(7F | 7E) ?? 0F (8E | 8F) ?? ?? ?? ??}

    condition:
        any of them
}
"""

align = lambda size, alignment: ((size // alignment) + 1) * alignment

def patch(dest, seq):
    for i, c in enumerate(seq):
        idc.PatchByte(dest+i, ord(c))

# define eflags register structure
class EFLAGS:
    CF = 1 << 0
    PF = 1 << 2
    AF = 1 << 4
    ZF = 1 << 6
    SF = 1 << 7
    TF = 1 << 8
    IF = 1 << 9
    DF = 1 << 10
    OF = 1 << 11

def path_jumps_with_constant_condition():
    # alloc code
    mu.mem_map(start, align(end - start, 0x1000))
    # alloc stack
    mu.mem_map(0x3C000, 0x1000)
    # map buffer to code section
    mu.mem_write(start, data)

    count = 0
    match = list()

    # locate rule
    for hit in matches:
        if hit.rule == 'jumps_with_constant_condition':
            match = hit.strings

    for hit in match:
        (offset, name, pattern) = hit
        pattern_size = len(pattern)

        # set esp to the middle of the stack every iteration
        mu.reg_write(UC_X86_REG_ESP, 0x3C500)

        # disassemble instructions at the end of pattern,
        # we are looking for inderect jump instructions.
        # 12 - max size of 2 jmp near instructions.
        dis =  list(md.disasm(data[offset + pattern_size:offset + pattern_size + 12], start + offset + pattern_size))
        # if we couldn't disassemble opcodes
        if (not dis):
            continue
        # or if the first instruction is not a conditional jump
        if (X86_GRP_BRANCH_RELATIVE not in dis[0].groups) or (X86_GRP_JUMP not in dis[0].groups):
            continue
        # emulate
        try:
            mu.emu_start(start + offset, start + offset + pattern_size)
        except UcError as e:
            eip = mu.reg_read(UC_X86_REG_EIP)
            print binascii.hexlify(pattern), hex(offset + start), hex(eip), e

        flags = mu.reg_read(UC_X86_REG_EFLAGS)
        do_patching = False
        for i in md.disasm(data[offset + pattern_size:offset + pattern_size + 12], start + offset + pattern_size):
            if (X86_GRP_JUMP in i.groups) and (X86_GRP_BRANCH_RELATIVE in i.groups):

                # http://www.unixwiz.net/techtips/x86-jumps.html
                if i.id == X86_INS_JO:
                    if flags & EFLAGS.OF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JNO:
                    if not (flags & EFLAGS.OF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JB:
                    if flags & EFLAGS.CF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JAE:
                    if not (flags & EFLAGS.CF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JE:
                    if flags & EFLAGS.ZF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JNE:
                    if not (flags & EFLAGS.ZF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JBE:
                    if flags & (EFLAGS.CF | EFLAGS.ZF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JA:
                    if not (flags & (EFLAGS.CF | EFLAGS.ZF)):
                        do_patching = True
                        break
                elif i.id == X86_INS_JS:
                    if flags & EFLAGS.SF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JNS:
                    if not (flags & EFLAGS.SF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JP:
                    if flags & EFLAGS.PF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JNP:
                    if not (flags & EFLAGS.PF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JL:
                    if flags & EFLAGS.SF != flags & EFLAGS.OF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JGE:
                    if flags & EFLAGS.SF == flags & EFLAGS.OF:
                        do_patching = True
                        break
                elif i.id == X86_INS_JLE:
                    if (flags & EFLAGS.ZF) or (flags & EFLAGS.SF != flags & EFLAGS.OF):
                        do_patching = True
                        break
                elif i.id == X86_INS_JG:
                    if not ((flags & EFLAGS.ZF) and (flags & EFLAGS.SF == flags & EFLAGS.OF)):
                        do_patching = True
                        break
                else:
                    print "unknown jmp 0x%x" % i.address
                    break
        if do_patching:
            count += 1
            # VA
            jump_location_address = int(i.op_str, 16)
            dis = list(md.disasm(data[jump_location_address - start:jump_location_address - start + 6], jump_location_address))
            bytes_to_patch = 0
            if not dis:
                print "no disasm at 0x%x" % jump_location_address
                continue

            # there are currently only 3 types of patterns (03.07.2019)
            #
            # 1. mov reg, [esp + x]
            #    add esp, y
            #
            # 2. pop reg
            #
            # 3. pop reg
            #    add esp, y
            if (dis[0].mnemonic == 'mov') and ('esp' in dis[0].op_str):
                bytes_to_patch = 3
                if len(dis) > 1:
                    if (dis[1].mnemonic == "add") and ('esp' in dis[1].op_str):
                        bytes_to_patch = 6
            if dis[0].mnemonic == 'pop':
                bytes_to_patch = 1
                if len(dis) > 1:
                    if (dis[1].mnemonic == 'add') and ('esp' in dis[1].op_str):
                        bytes_to_patch = 4

            # more checks just to be sure
            if bytes_to_patch:
                patch(int(i.op_str, 16), "\x90" * bytes_to_patch)
                patch(start + offset, "\x90" * (i.address - start - offset))
                if i.size == 6:
                    # if jump is near
                    patch(i.address, "\x90\xE9")
                else:
                    # if jump is short
                    patch(i.address, "\xEB")

                # insert junk after the patch so IDA wont disassemble furter
                patch(i.address + i.size, "\xCC" * (jump_location_address - i.address - i.size))
            else:
                print "0 bytes to patch at 0x%x" % jump_location_address
    print "patched %d places!" % count

def patch_inderect_jumps():
    print "patching inderect jumps.."
    count = 0
    match = list()
    for hit in matches:
        if hit.rule == 'inderect_jumps':
            match = hit.strings
    for hit in match:
        (offset, name, pattern) = hit
        pattern_size = len(pattern)
        dis = list(md.disasm(data[offset:offset + pattern_size], start + offset))
        # we MUST find only 2 instructions (2 jumps) disassembled
        if len(dis) != 2:
            continue
        # both jumps must point to the same location
        if int(dis[0].op_str, 16) != int(dis[1].op_str, 16):
            continue
        if dis[0].size == 6:
            patch(dis[0].address, "\x90\xE9")
        else:
            patch(dis[0].address, "\xEB")
        patch(dis[0].address + dis[0].size, "\xCC" * (int(dis[0].op_str, 16) - dis[0].address - dis[0].size))
        count += 1
    print "patched %d inderect jumps!" % count

if __name__ == "__main__":
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    start = idc.get_segm_by_sel(0)
    end = idc.get_segm_end(start)
    data = idaapi.get_many_bytes(start, end - start)
    matches = yara.compile(source=rules).match(data=data)
    path_jumps_with_constant_condition()
    patch_inderect_jumps()

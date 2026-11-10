"""Statically identify the installed ARM64 payload's compiler guard accesses.
Reads ELF bytes and uses the system LLVM disassembler. Executes no payload code.
"""
import ctypes as c
import hashlib
import json
from pathlib import Path
import re
import struct
from tls_register_flow import tp_provenance


def branch_target(word, pc):
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return pc+immediate*4


def external_load_thunks(elf, rows, start, size):
    """Recognize only LDR; B-back veneers, preserving all other registers."""
    result = {}
    for pc, word, _ in rows:
        if word & 0xfc000000 != 0x14000000:
            continue
        target = branch_target(word, pc)
        if start <= target < start+size:
            continue
        try:
            load, branch = elf.word(target), elf.word(target+4)
        except ValueError:
            continue
        if load & 0xffc00000 != 0xf9400000 or branch & 0xfc000000 != 0x14000000:
            continue
        continuation = branch_target(branch, target+4)
        if start <= continuation < start+size:
            result[pc] = (continuation, {load & 31})
    return result


class ELF:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self.header = struct.unpack_from('<16sHHIQQQIHHHHHH', self.data)
        e = self.header
        self.sections = [struct.unpack_from('<IIQQQQIIQQ', self.data, e[6]+i*e[11]) for i in range(e[12])]
        names = self.sections[e[13]]
        strings = self.data[names[4]:names[4]+names[5]]
        self.named = {strings[s[0]:].split(b'\0', 1)[0].decode(): s for s in self.sections}
        self.loads = [struct.unpack_from('<IIQQQQQQ', self.data, e[5]+i*e[9]) for i in range(e[10])]

    def offset(self, address):
        for p in self.loads:
            if p[0] == 1 and p[3] <= address < p[3]+p[5]:
                return p[2]+address-p[3]
        raise ValueError(f'No file bytes for {address:#x}')

    def word(self, address):
        return struct.unpack_from('<I', self.data, self.offset(address))[0]

    def function_ranges(self):
        s = self.named['.eh_frame_hdr']
        assert self.data[s[4]:s[4]+4] == bytes([1, 0x1b, 3, 0x3b])
        count = struct.unpack_from('<I', self.data, s[4]+8)[0]
        result = []
        for i in range(count):
            start, fde = struct.unpack_from('<ii', self.data, s[4]+12+i*8)
            start, fde = start+s[3], fde+s[3]
            pos = self.offset(fde)
            encoded, size = struct.unpack_from('<iI', self.data, pos+8)
            assert encoded+fde+8 == start
            if size:
                result.append((start, size))
        return result


class Disassembler:
    def __init__(self):
        try:
            self.lib = c.CDLL('/usr/lib/libLLVM-15.so')
        except OSError:
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
            self.capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
            self.lib = None
            return
        for name in ['LLVMInitializeAArch64TargetInfo', 'LLVMInitializeAArch64Target',
                     'LLVMInitializeAArch64TargetMC', 'LLVMInitializeAArch64Disassembler']:
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = [], None
            fn()
        self.lib.LLVMCreateDisasm.argtypes = [c.c_char_p, c.c_void_p, c.c_int, c.c_void_p, c.c_void_p]
        self.lib.LLVMCreateDisasm.restype = c.c_void_p
        self.context = self.lib.LLVMCreateDisasm(b'aarch64-linux-android', None, 0, None, None)
        assert self.context
        self.lib.LLVMDisasmInstruction.argtypes = [c.c_void_p, c.POINTER(c.c_uint8), c.c_uint64,
                                                 c.c_uint64, c.c_char_p, c.c_size_t]
        self.lib.LLVMDisasmInstruction.restype = c.c_size_t

    def instruction(self, word, pc):
        if self.lib is None:
            instruction = next(self.capstone.disasm(struct.pack('<I', word), pc))
            text = instruction.mnemonic+' '+instruction.op_str
            if instruction.mnemonic in {'b', 'bl'} or instruction.mnemonic.startswith('b.'):
                target = int(instruction.op_str.lstrip('#'), 0)
                return instruction.mnemonic+' #'+str(target-pc)
            return re.sub(r'#(-?0x[0-9a-f]+)', lambda match: '#'+str(int(match[1], 0)), text).strip()
        data = (c.c_uint8*4).from_buffer_copy(struct.pack('<I', word))
        out = c.create_string_buffer(256)
        assert self.lib.LLVMDisasmInstruction(self.context, data, 4, pc, out, len(out)) == 4
        return out.value.decode().strip().replace('\t', ' ')


def main():
    elf = ELF('/recalbox/share/roms/ports/gtasa/libGame.so')
    assert hashlib.sha256(elf.data).hexdigest() == '4c6a7445e30b27afdda781302e4db9bac89c28fc1181b68b1eef16f84d6a282e', 'Unsupported payload for this version-bound catalog'
    llvm = Disassembler()
    dynamic = elf.named['.dynsym']
    names = elf.sections[dynamic[6]]
    strings = elf.data[names[4]:names[4]+names[5]]
    relocations = elf.named['.rela.plt']
    fail_plt = None
    for index, pos in enumerate(range(relocations[4], relocations[4]+relocations[5], 24)):
        _, info, _ = struct.unpack_from('<QQq',elf.data,pos)
        name = struct.unpack_from('<I',elf.data,dynamic[4]+(info>>32)*24)[0]
        if strings[name:].split(b'\0',1)[0] == b'__stack_chk_fail':
            fail_plt = elf.named['.plt'][3]+32+16*index
    assert fail_plt == 0x7f47b0
    records, unknown, sites, misses, rejected = [], [], [], [], []
    for start, size in elf.function_ranges():
        words = [elf.word(pc) for pc in range(start, start+size-3, 4)]
        mrs = [i for i, word in enumerate(words) if word & 0xffffffe0 == 0xd53bd040]
        if not mrs:
            continue
        rows = [(start+4*i, word, llvm.instruction(word, start+4*i)) for i, word in enumerate(words)]
        by_address = {row[0]: row[2] for row in rows}
        def is_failure_target(pc):
            for _ in range(4):
                text = by_address.get(pc,'')
                if text.startswith('bl #'):
                    return pc+int(text.split('#')[1],0) == fail_plt
                if text.startswith('b #'):
                    pc += int(text.split('#')[1],0)
                elif text == 'nop':
                    pc += 4
                else:
                    return False
            return False
        tp_regs = {words[i] & 31 for i in mrs}
        sp, fp = 0, None
        fp_delta = 0
        for _, _, text in rows[:80]:
            match = re.match(r'sub sp, sp, #(\d+)(?:, lsl #(\d+))?', text)
            if match:
                sp -= int(match[1]) << int(match[2] or 0)
            match = re.search(r'\[sp, #(-?\d+)\]!', text)
            if match:
                sp += int(match[1])
            if text == 'mov x29, sp':
                fp = sp
            match = re.match(r'add x29, sp, #(\d+)', text)
            if match:
                fp = sp+int(match[1])
            if text.startswith(('bl ', 'blr ')):
                break
        if fp is not None:
            fp_delta = fp-sp
        def stack_operand(text):
            match = re.search(r'\[(sp|x29)(?:, #(-?\d+))?\]', text)
            return ('sp', int(match[2] or 0)+(fp_delta if match[1]=='x29' else 0)) if match else None
        guard_slots = set()
        picked = set()
        for mrs_index in mrs:
            base = words[mrs_index] & 31
            for i in range(mrs_index+1, min(mrs_index+64, len(rows))):
                word = rows[i][1]
                if word & 0xffc00000 == 0xf9400000 and (word >> 5) & 31 == base and ((word >> 10) & 4095)*8 == 40:
                    reg = f'x{word & 31}'
                    for j in range(i+1, min(i+24, len(rows))):
                        text = rows[j][2]
                        if re.match(r'(str|stur) '+reg+r',', text) and stack_operand(text):
                            guard_slots.add(stack_operand(text))
                            picked.add(i)
                            break
                        if text.startswith(('bl ', 'blr ')):
                            break
                        if re.match(r'\w+ [xw]'+str(word & 31)+r',',text) and not text.startswith(('str ', 'stur ', 'stp ', 'cmp ', 'tst ')):
                            break
                    break
                text = rows[i][2]
                if text.startswith(('bl ', 'blr ')):
                    break
                if re.match(r'\w+ [xw]'+str(base)+r',',text) and not text.startswith(('str ', 'stur ', 'stp ', 'cmp ', 'tst ')):
                    break
        for i, (_, word, _) in enumerate(rows):
            if word & 0xffc00000 != 0xf9400000 or ((word >> 10) & 4095)*8 != 40:
                continue
            if (word >> 5) & 31 >= 29:  # Saved stack/frame loads are not TP loads.
                continue
            reg = f'x{word & 31}'
            for j in range(max(0, i-4), min(i+5, len(rows))):
                text = rows[j][2]
                match = re.match(r'(ldr|ldur) (x\d+),', text)
                if j == i or not match or stack_operand(text) not in guard_slots:
                    continue
                saved = match[2]
                for k in range(max(i,j)+1,min(max(i,j)+40,len(rows)-1)):
                    text = rows[k][2]
                    if (text.startswith('cmp ') and re.search(r'\b'+reg+r'\b',text)
                            and re.search(r'\b'+saved+r'\b',text)):
                        branch = rows[k+1][2]
                        if branch.startswith('b.ne #') and is_failure_target(rows[k+1][0]+int(branch.split('#')[1],0)):
                            picked.add(i)
                        break
                    if text.startswith(('bl ', 'blr ', 'ret', 'b.','b #','cbz ','cbnz ','tbz ','tbnz ')):
                        break
                    if re.match(r'\w+ [xw](?:'+str(word&31)+'|'+saved[1:]+r'),',text) and not text.startswith(('str ','stur ','stp ','cmp ','tst ')):
                        break
        # A nearby stack comparison is insufficient: the load base must still
        # contain TPIDR_EL0 on every path. Otherwise an object-field load can
        # be mistaken for the following guard load that reuses its destination.
        provenance = tp_provenance(b''.join(struct.pack('<I', word) for word in words),
                                   start, noreturn_targets={fail_plt},
                                   external_branches=external_load_thunks(elf, rows, start, size))
        unsafe = {i for i in picked
                  if (rows[i][1] >> 5) & 31 not in provenance[rows[i][0]]}
        rejected.extend({'address': rows[i][0], 'word': rows[i][1]} for i in sorted(unsafe))
        picked -= unsafe
        for i in sorted(picked):
            sites.append({'address': rows[i][0], 'word': rows[i][1]})
        if picked:
            assert any(text.startswith('bl #') and pc+int(text.split('#')[1],0)==fail_plt
                       for pc,_,text in rows),hex(start)
        if len(picked) < 2:
            misses.append({'start': hex(start), 'size': size, 'picked': len(picked),
                           'guard_slots': list(guard_slots), 'head': [r[2] for r in rows[:20]]})
        loads = [i for i, (_, w, _) in enumerate(rows)
                 if w & 0xffc00000 == 0xf9400000 and (w >> 5) & 31 in tp_regs
                 and ((w >> 10) & 4095)*8 == 40]
        records.append({'start': start, 'size': size, 'mrs': [rows[i][0] for i in mrs],
                        'loads': [{'address': rows[i][0], 'word': rows[i][1],
                                   'assembly': rows[i][2],
                                   'nearby': [row[2] for row in rows[max(0,i-2):i+7]]}
                                  for i in loads]})
        if len(loads) != 2*len(mrs):
            unknown.append({'start': hex(start), 'size': size, 'mrs': len(mrs),
                            'loads': len(loads), 'examples': [rows[i][2] for i in loads][:6]})
    output = {'sha256': hashlib.sha256(elf.data).hexdigest(), 'functions': records,
              'sites': sites, 'rejected_non_tp': rejected}
    Path('validation/tls-site-audit.json').write_text(json.dumps(output, indent=2)+'\n')
    print('Functions with TP reads:', len(records), 'TP reads:', sum(len(r['mrs']) for r in records),
          'candidate loads:', sum(len(r['loads']) for r in records))
    print('Matched guard sites:',len(sites),'Functions with <2 sites:',len(misses))
    print('Rejected non-TP field loads:', len(rejected))
    print(json.dumps(misses[:20],indent=2))
    if misses:
        raise SystemExit('Guard catalog incomplete; no runtime header generated')
    assert len(sites)==len({s['address'] for s in sites})
    entries=[]
    for site in sorted(sites,key=lambda s:s['address']):
        assert site['word'] & ~1023 == 0xf9401400
        assert (site['word'] >> 5) & 31 < 29
        assert site['address']%4 == 0 and site['address'] < 0x1000000
        entries.append((site['address']//4<<10)|(site['word']&1023))
    header='/* Generated from validated compiler guard save/check sequences.\n'
    header+=' * Payload SHA256: '+output['sha256']+'\n'
    header+=' * Only LDR guard-offset immediates are adapted; comparisons remain. */\n'
    header+='static const uint32_t bionic_tls_guard_sites[] = {\n'
    for pos in range(0,len(entries),8):
        header+='  '+', '.join(f'0x{entry:08x}u' for entry in entries[pos:pos+8])+',\n'
    header+='};\n'
    Path('source/bionic_tls_sites.inc').write_text(header)
    print('Generated guarded runtime catalog:',len(entries),'sites')


if __name__ == '__main__':
    main()

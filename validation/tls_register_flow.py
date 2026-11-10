"""Conservative AArch64 TP provenance for the offline guard-site generator.

Requires Capstone 5 (development tool only). A register is accepted at an
instruction only if it contains TPIDR_EL0 on every incoming control-flow path.
Register overwrites, pair loads and call-clobbered registers are accounted for.
"""
from collections import deque
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM


def gpr(instruction, register):
    name = instruction.reg_name(register)
    name = {'fp': 'x29', 'lr': 'x30'}.get(name, name)
    if name in {'sp', 'wsp'}:
        return 31
    match = re.fullmatch('[xw](\d+)', name)
    return int(match[1]) if match else None


def switch_successors(code, start, read_bytes):
    """Resolve bounds-checked byte/halfword relative AArch64 jump tables."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    rows = list(decoder.disasm(code, start))
    result = {}
    for branch_index, branch in enumerate(rows):
        if branch.mnemonic != 'br':
            continue
        destination = gpr(branch, branch.operands[0].reg)
        # A few independent instructions can appear between ADD and BR.
        add_index = next((i for i in range(branch_index-1, max(-1, branch_index-6), -1)
                          if destination in {gpr(rows[i], reg) for reg in rows[i].regs_access()[1]}), None)
        if add_index is None:
            continue  # ordinary indirect tail call
        add = rows[add_index]
        if (add.mnemonic != 'add' or len(add.operands) != 3
                or any(op.type != ARM64_OP_REG for op in add.operands)):
            continue
        offset_register = gpr(add, add.operands[2].reg)
        load_index = next((i for i in range(add_index-1, max(-1, add_index-5), -1)
                           if rows[i].mnemonic in {'ldrb', 'ldrh'}
                           and gpr(rows[i], rows[i].operands[0].reg) == offset_register), None)
        if load_index is None:
            continue
        load = rows[load_index]
        mem = next(op for op in load.operands if op.type == ARM64_OP_MEM)
        if not mem.mem.index:
            continue
        _, states = tp_provenance(code, start, indirect_branches=result,
                                  return_states=True)
        state = states.get(load.address, {})
        def address_constant(register):
            value = state.get(('r', register))
            return value[1] if isinstance(value, tuple) and value[0] == 'address' else None
        table = address_constant(gpr(load, mem.mem.base))
        anchor = address_constant(gpr(add, add.operands[1].reg))
        index_register = gpr(load, mem.mem.index)
        bound = None
        for i in range(load_index-1, max(-1, load_index-64), -1):
            row = rows[i]
            operands = row.operands
            if (row.mnemonic == 'mov' and len(operands) == 2
                    and all(op.type == ARM64_OP_REG for op in operands)
                    and gpr(row, operands[0].reg) == index_register):
                index_register = gpr(row, operands[1].reg)
            if (row.mnemonic == 'cmp' and len(operands) == 2
                    and operands[1].type == ARM64_OP_IMM
                    and gpr(row, operands[0].reg) == index_register
                    and any(r.mnemonic in {'b.hi', 'b.ls'} for r in rows[i+1:min(load_index, i+10)])):
                bound = operands[1].imm
                break
        if table is None or anchor is None or bound is None or not 0 <= bound < 65536:
            raise ValueError(f'Unresolved guarded switch table at {branch.address:#x}')
        width = 1 if load.mnemonic == 'ldrb' else 2
        raw = read_bytes(table+mem.mem.disp, width*(bound+1))
        if len(raw) != width*(bound+1):
            raise ValueError('Truncated switch table')
        offsets = struct.unpack('<'+('B' if width == 1 else 'H')*(bound+1), raw)
        targets = {anchor+(offset << add.operands[2].shift.value) for offset in offsets}
        if any(target % 4 or not start <= target < start+len(code) for target in targets):
            raise ValueError(f'Switch target outside guarded function at {branch.address:#x}')
        result[branch.address] = targets
    return result


def tp_provenance(code, start, noreturn_targets=(), external_branches=None,
                  indirect_branches=None, return_states=False):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    rows = list(decoder.disasm(code, start))
    if len(rows)*4 != len(code):
        raise ValueError(f'Incomplete AArch64 decode at {start:#x}')
    by_address = {row.address: i for i, row in enumerate(rows)}
    external_branches = external_branches or {}
    indirect_branches = indirect_branches or {}
    if not rows:
        return {}
    incoming = [None]*len(rows)
    # Values are TP or offsets relative to the entry stack pointer. Stack slots
    # matter: optimized epilogues can reload a spilled TP into another register.
    incoming[0] = {('r', 31): 0}
    todo = deque([0])
    while todo:
        index = todo.popleft()
        instruction = rows[index]
        before = incoming[index]
        state = dict(before)
        for register in instruction.regs_access()[1]:
            number = gpr(instruction, register)
            if number is not None:
                state.pop(('r', number), None)
        op, operands = instruction.mnemonic, instruction.operands
        if op == 'mrs' and instruction.op_str.endswith('tpidr_el0'):
            state['r', gpr(instruction, operands[0].reg)] = 'tp'
        elif op in {'adr', 'adrp'}:
            state['r', gpr(instruction, operands[0].reg)] = ('address', operands[1].imm)
        elif (op == 'mov' and len(operands) == 2
              and all(operand.type == ARM64_OP_REG for operand in operands)
              and instruction.reg_name(operands[0].reg)[:1] not in {'w'}):
            source = ('r', gpr(instruction, operands[1].reg))
            if source in before:
                state['r', gpr(instruction, operands[0].reg)] = before[source]
        elif (op in {'add', 'sub'} and len(operands) == 3
              and operands[0].type == operands[1].type == ARM64_OP_REG
              and not instruction.reg_name(operands[0].reg).startswith('w')
              and operands[2].type == ARM64_OP_IMM):
            source = before.get(('r', gpr(instruction, operands[1].reg)))
            if isinstance(source, int):
                amount = operands[2].imm << operands[2].shift.value
                state['r', gpr(instruction, operands[0].reg)] = source + (amount if op == 'add' else -amount)
            elif isinstance(source, tuple) and source[0] == 'address':
                amount = operands[2].imm << operands[2].shift.value
                state['r', gpr(instruction, operands[0].reg)] = ('address', source[1]+(amount if op == 'add' else -amount))
        mem = next((operand for operand in operands if operand.type == ARM64_OP_MEM), None)
        if mem is not None:
            base = before.get(('r', gpr(instruction, mem.mem.base)))
            if isinstance(base, int) and not mem.mem.index:
                address = base+mem.mem.disp
                pair = op in {'stp', 'ldp'}
                targets = operands[:2] if pair else operands[:1]
                is_store = op.startswith(('str', 'stur', 'stp'))
                is_load = op.startswith(('ldr', 'ldur', 'ldp'))
                for target_index, operand in enumerate(targets):
                    if operand.type != ARM64_OP_REG:
                        continue
                    name = instruction.reg_name(operand.reg)
                    width = 16 if name.startswith('q') else 8 if name.startswith(('x', 'd')) else 4
                    if op.endswith('b'):
                        width = 1
                    elif op.endswith('h'):
                        width = 2
                    slot = address+target_index*width
                    if is_store:
                        for key in list(state):
                            if key[0] == 'm' and slot-7 <= key[1] < slot+width:
                                state.pop(key)
                        value = before.get(('r', gpr(instruction, operand.reg)))
                        if width == 8 and value is not None:
                            state['m', slot] = value
                    elif is_load and width == 8:
                        value = before.get(('m', slot))
                        if value is not None:
                            state['r', gpr(instruction, operand.reg)] = value
                if instruction.writeback:
                    delta = mem.mem.disp
                    if operands[-1].type == ARM64_OP_IMM:
                        delta = operands[-1].imm
                    state['r', gpr(instruction, mem.mem.base)] = base+delta
        if op in {'bl', 'blr'}:
            for register in range(19):
                state.pop(('r', register), None)
        successors = []
        if op == 'br' and instruction.address in indirect_branches:
            successors.extend(by_address[address] for address in indirect_branches[instruction.address])
        no_return_call = (op == 'bl' and operands and operands[0].type == ARM64_OP_IMM
                          and operands[0].imm in noreturn_targets)
        if not no_return_call and op not in {'ret', 'br', 'b'} and index+1 < len(rows):
            successors.append(index+1)
        if op == 'b' or op.startswith('b.') or op in {'cbz', 'cbnz', 'tbz', 'tbnz'}:
            immediate = next((operand.imm for operand in reversed(operands)
                              if operand.type == ARM64_OP_IMM), None)
            if immediate in by_address:
                successors.append(by_address[immediate])
            elif op == 'b' and instruction.address in external_branches:
                continuation, clobbered = external_branches[instruction.address]
                for register in clobbered:
                    state.pop(('r', register), None)
                if continuation in by_address:
                    successors.append(by_address[continuation])
        for successor in successors:
            updated = dict(state) if incoming[successor] is None else {
                key: value for key, value in incoming[successor].items() if state.get(key) == value}
            if incoming[successor] != updated:
                incoming[successor] = updated
                todo.append(successor)
    provenance = {row.address: frozenset(key[1] for key, value in (incoming[i] or {}).items()
                                        if key[0] == 'r' and value == 'tp')
                  for i, row in enumerate(rows)}
    if return_states:
        return provenance, {row.address: incoming[i] or {} for i, row in enumerate(rows)}
    return provenance

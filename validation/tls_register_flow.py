"""Conservative AArch64 TP provenance for the offline guard-site generator.

Requires Capstone 5 (development tool only). A register is accepted at an
instruction only if it contains TPIDR_EL0 on every incoming control-flow path.
Register overwrites, pair loads and call-clobbered registers are accounted for.
"""
from collections import deque
import re

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM


def gpr(instruction, register):
    name = instruction.reg_name(register)
    name = {'fp': 'x29', 'lr': 'x30'}.get(name, name)
    if name in {'sp', 'wsp'}:
        return 31
    match = re.fullmatch('[xw](\d+)', name)
    return int(match[1]) if match else None


def tp_provenance(code, start, noreturn_targets=(), external_branches=None):
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    rows = list(decoder.disasm(code, start))
    if len(rows)*4 != len(code):
        raise ValueError(f'Incomplete AArch64 decode at {start:#x}')
    by_address = {row.address: i for i, row in enumerate(rows)}
    external_branches = external_branches or {}
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
    return {row.address: frozenset(key[1] for key, value in (incoming[i] or {}).items()
                                  if key[0] == 'r' and value == 'tp')
            for i, row in enumerate(rows)}

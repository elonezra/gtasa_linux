"""Synthetic regressions for TP provenance; no Android library is required."""
import struct
import unittest

from tls_register_flow import tp_provenance, switch_successors
from collect_tls_sites import guard_failure_edge


def flow(*words):
    return tp_provenance(struct.pack('<'+'I'*len(words), *words), 0x1000)


class ProvenanceTests(unittest.TestCase):
    def test_guard_failure_direct_conditional_branch(self):
        rows = [(0x1000, 0, 'cmp x8, x9'), (0x1004, 0, 'b.ne #4092')]
        self.assertTrue(guard_failure_edge(rows, 0, lambda pc: pc == 0x2000))

    def test_guard_success_branch_then_unconditional_failure(self):
        rows = [(0x1000, 0, 'cmp x8, x9'), (0x1004, 0, 'b.eq #16'),
                (0x1008, 0, 'b #4088')]
        self.assertTrue(guard_failure_edge(rows, 0, lambda pc: pc == 0x2000))
        self.assertFalse(guard_failure_edge(rows, 0, lambda pc: pc == 0x3000))

    def test_object_load_before_guard_check_is_not_a_tp_load(self):
        result = flow(0xd53bd056,  # mrs x22, tpidr_el0
                      0xf94016c8,  # ldr x8, [x22, #40]
                      0xf90007e8,  # str x8, [sp, #8]
                      0xaa0003f3,  # mov x19, x0 (object)
                      0xf9401668,  # ldr x8, [x19, #40] -- MUST NOT PATCH
                      0xf94016c8,  # ldr x8, [x22, #40] -- true guard
                      0xf94007e9,  # ldr x9, [sp, #8]
                      0xeb09011f,  # cmp x8, x9
                      0xd65f03c0)
        self.assertNotIn(19, result[0x1010])
        self.assertIn(22, result[0x1014])

    def test_reused_thread_pointer_register_is_rejected(self):
        result = flow(0xd53bd048,  # mrs x8, tpidr_el0
                      0xaa0003e8,  # mov x8, x0 (object)
                      0xf9401509,  # ldr x9, [x8, #40]
                      0xd65f03c0)
        self.assertNotIn(8, result[0x1008])

    def test_call_clobbers_volatile_but_preserves_saved_register(self):
        result = flow(0xd53bd048, 0xd53bd056, 0x94000000,
                      0xd503201f, 0xd65f03c0)
        self.assertNotIn(8, result[0x100c])
        self.assertIn(22, result[0x100c])

    def test_branch_join_requires_tp_on_both_paths(self):
        result = flow(0xd53bd053,  # mrs x19, tpidr_el0
                      0x54000040,  # b.eq +8 (skip object overwrite)
                      0xaa0003f3,  # mov x19, x0
                      0xf9401668,  # ldr x8, [x19,#40]
                      0xd65f03c0)
        self.assertNotIn(19, result[0x100c])

    def test_register_copy_and_pair_load_overwrite(self):
        result = flow(0xd53bd053,  # mrs x19, tpidr_el0
                      0xaa1303f6,  # mov x22, x19
                      0xa94053f3,  # ldp x19, x20, [sp]
                      0xd503201f, 0xd65f03c0)
        self.assertNotIn(19, result[0x100c])
        self.assertIn(22, result[0x100c])

    def test_spilled_pointer_reload_survives_host_call(self):
        result = flow(0xd53bd048,  # mrs x8, tpidr_el0
                      0xf90007e8,  # str x8, [sp,#8]
                      0x94000000,  # bl (clobbers x8)
                      0xf94007f3,  # ldr x19, [sp,#8]
                      0xf9401668,  # ldr x8, [x19,#40]
                      0xd65f03c0)
        self.assertIn(19, result[0x1010])

    def test_overwritten_spill_is_not_a_pointer(self):
        result = flow(0xd53bd048, 0xf90007e8,
                      0xb9000bff,  # str wzr, [sp,#8] overwrites half of pointer
                      0xf94007f3, 0xf9401668, 0xd65f03c0)
        self.assertNotIn(19, result[0x1010])

    def test_noreturn_failure_does_not_flow_into_other_exit_paths(self):
        # The failure block sits before an out-of-line normal continuation.
        words = [0xd53bd053, 0x54000060, 0x94000400,
                 0xaa0003f3, 0xf9401668, 0xd65f03c0]
        result = tp_provenance(struct.pack('<6I', *words), 0x1000,
                               noreturn_targets={0x2008})
        self.assertIn(19, result[0x1010])
        without_noreturn = tp_provenance(struct.pack('<6I', *words), 0x1000)
        self.assertNotIn(19, without_noreturn[0x1010])

    def test_external_load_veneer_preserves_other_registers(self):
        words = [0xd53bd055, 0x14000400, 0xf94016a8, 0xd65f03c0]
        result = tp_provenance(struct.pack('<4I', *words), 0x1000,
                               external_branches={0x1004: (0x1008, {20})})
        self.assertIn(21, result[0x1008])

    def test_indirect_switch_keeps_guard_checks_in_every_case(self):
        def adr(register, displacement):
            immediate = displacement & 0x1fffff
            return 0x10000000 | ((immediate & 3) << 29) | ((immediate >> 2) << 5) | register
        words = [0xd503201f]*16
        words[:8] = [0xd53bd058,  # mrs x24, tpidr_el0
                     0x7100041f,  # cmp w0,#1
                     0x54000188,  # b.hi default at 0x1038
                     adr(9, 0x3000-0x100c),
                     adr(10, 0x1020-0x1010),
                     0x7860792b,  # ldrh w11,[x9,x0,lsl #1]
                     0x8b0b094a,  # add x10,x10,x11,lsl #2
                     0xd61f0140]  # br x10
        for index in [8, 12, 14]:
            words[index:index+2] = [0xf9401708, 0xd65f03c0]
        code = struct.pack('<16I', *words)
        def table(address, length):
            self.assertEqual((address, length), (0x3000, 4))
            return struct.pack('<2H', 0, 4)
        successors = switch_successors(code, 0x1000, table)
        self.assertEqual(successors, {0x101c: {0x1020, 0x1030}})
        result = tp_provenance(code, 0x1000, indirect_branches=successors)
        for address in [0x1020, 0x1030, 0x1038]:
            self.assertIn(24, result[address])
        without_switch = tp_provenance(code, 0x1000)
        self.assertNotIn(24, without_switch[0x1020])

    def test_invalid_switch_target_is_rejected(self):
        # Reuse the actual decoder path with a deliberately outside target.
        code = struct.pack('<8I', 0xd53bd058, 0x7100041f, 0x54000048,
                           0x1000ff49, 0x1000006a, 0x7860792b,
                           0x8b0b094a, 0xd61f0140)
        with self.assertRaises(ValueError):
            switch_successors(code, 0x1000, lambda address, length: b'\xff'*length)


if __name__ == '__main__':
    unittest.main()

"""Synthetic regressions for TP provenance; no Android library is required."""
import struct
import unittest

from tls_register_flow import tp_provenance


def flow(*words):
    return tp_provenance(struct.pack('<'+'I'*len(words), *words), 0x1000)


class ProvenanceTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()

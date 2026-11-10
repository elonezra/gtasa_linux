# Regenerating the exact-payload guard catalog

The generator is an offline development tool. It never executes Android code.
It requires Capstone 5.0.6; this dependency is not needed by the game at runtime.
LLVM-15 is optional and is used for formatted assembly when available.

From the repository root, with the owner's exact v2.11.311 library installed
at the path in `collect_tls_sites.py`:

```sh
python3 -m unittest discover -s validation -p test_tls_register_flow.py -v
python3 validation/collect_tls_sites.py
```

The candidate matcher requires compiler guard saves, stack-slot comparisons
and a failure branch. The additional control-flow analysis requires each load
base to contain TPIDR_EL0 on every incoming path. It accounts for register
overwrites, pair loads, caller-clobbered registers, stack spills, frame offsets,
non-returning stack-check failures and verified LDR/B-back veneers. Unsupported
flow is rejected rather than treated as proof of a guard access. Generation
fails if any guarded function has fewer than two validated sites.

The old proximity-only matcher incorrectly selected CEntity::Render+0x198
(0x48d6e8): an entity-field load immediately before the actual guard load at
0x48d6f4. The runtime translation changed its offset from 0x28 to 0x10, causing
the renderer to write position bytes into entity flags. A hardware watchpoint
on the Pi established the actual writer. Regression tests retain the true
guard and exclude the entity-field load.

Do not upload the owner's Android library, screenshots, object dumps or private
runtime logs. Rebuild native artifacts through the existing Containerfile.

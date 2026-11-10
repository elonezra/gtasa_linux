# Recalbox 16KB loader validation

The recalbox-16k branch builds ARM64 artifacts without publishing an OCI image.
The workflow first runs tests/elf_pages_test.c using synthetic ELF data, then
uses the upstream Containerfile to build the port and run CTest.
The separate elf-pages-test-arm64 artifact is for a later real 16KB kernel check.

Static inspection of the installed libGame.so and libc++_shared.so found no
shared RX/RW host pages at 16KB. Both have PT_LOAD p_align=0x4000. Their exact
vaddr/memsz/flags are covered by installed_layout_test in the C regression.
Both are accepted at 4KB and 16KB geometry and rejected at 64KB geometry.
No proprietary payload bytes or game assets are included in these tests.

To repeat the read-only ELF audit (Python 3.11+):

```sh
python3 validation/inspect_elf_pages.py --page-size 16384 /path/to/libGame.so /path/to/libc++_shared.so
```

A successful CI build does not establish Recalbox dependency compatibility or
working gameplay. Inspect native linkage and run the synthetic test on the
actual 16KB host before a controlled TV test. No game or APK code has been
executed during source preparation and static validation.

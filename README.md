# leveldb-mcne
&emsp;一个使LevelDB支持简单的异或加密的扩展。

## 特性
&emsp;在打开LevelDB时使用`McneWrapper`启用异或加密。默认的异或加密密钥为`"88329851"`。
```cpp
#include "leveldb/db.h"
#include "leveldb_mcne.h"

leveldb::Options opt;
opt.env = new McneWrapper(leveldb::Env::Default());

leveldb::DB db;
leveldb::DB::Open(opt, "test/db", &db);
```

&emsp;也可将密钥设置为任意非0长度字节数组。若传入的密钥长度为0，则数据库不会被加密。若需要与网易版我的世界兼容则只能使用8字节长度密钥。
```cpp
// 示例: 密钥为testaaab
opt.env = new McneWrapper(
  leveldb::Env::Default()
  "testaaab"
);
```

&emsp;数据库除`.log`与`LOCK`外的所有文件均会被加密。加密后文件开头4字节为固定魔数`80 1D 30 01`，其后的内容为密钥循环与原文进行逐字节异或后的结果。

&emsp;使用`leveldb::InferDB`对数据库的密钥进行推断。该方法假定数据库密钥长度为8字节。使用`leveldb::EncryptDB`对数据库进行整体加密或解密。在调用这两个函数时传入的`Options`中的`Env`不能为`McneWrapper`。
```cpp
// 示例: 推断数据库密钥
std::string key;
leveldb::Options opt;
leveldb::InferDB(
  "path/to/db",
  opt,
  &key
);

// 示例: 整体解密数据库
leveldb::EncryptDB(
  "path/to/db",
  opt,
  key
);
```

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

&emsp;也可将密钥设置为任意非0长度字节数组。若传入的密钥长度为0，则数据库不会被加密。
```cpp
// 示例: 密钥为testaaab
opt.env = new McneWrapper(
  leveldb::Env::Default()
  "testaaab"
);
```

&emsp;数据库除.log外的所有文件均会被加密。加密后文件开头4字节为固定魔数`80 1D 30 01`，其后的内容为密钥循环与原文进行逐字节异或后的结果。
# John the Ripper 项目框架与压缩包破解原理分析

## 一、项目总体框架

John the Ripper（JtR）是一款开源密码破解工具，其核心架构由以下几个层次组成：

```
┌─────────────────────────────────────────────────────┐
│                   用户接口层 (john.c)                 │
│          命令行参数解析、破解模式调度、进度报告          │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│              破解引擎层 (cracker.c)                   │
│     候选密码生成、多线程/OpenMPI 调度、命中检测         │
└──────┬─────────────┬──────────────────┬─────────────┘
       │             │                  │
┌──────▼──┐   ┌──────▼──────┐   ┌──────▼──────┐
│单词表模式│   │  单破解模式  │   │  增量模式   │
│(wordlist)│   │  (single)   │   │(incremental)│
└─────────┘   └─────────────┘   └─────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│           格式插件层 (formats.c / *_fmt_plug.c)       │
│   每种哈希/加密格式都有独立插件，实现统一的 fmt_main 接口│
└─────────────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│           散列加载层 (loader.c)                        │
│       从文件读取散列/密文、组织 db_main 数据库结构       │
└─────────────────────────────────────────────────────┘
```

### 1.1 核心接口：`fmt_main` 结构体

每个格式插件（`*_fmt_plug.c`）都必须实现 `formats.h` 中定义的 `fmt_main` 结构，其关键方法如下：

| 方法 | 作用 |
|------|------|
| `valid(ciphertext)` | 判断密文字符串是否属于本格式 |
| `salt(ciphertext)` | 从密文中提取盐值（内部表示） |
| `binary(ciphertext)` | 从密文中提取期望的二进制摘要 |
| `set_salt(salt)` | 设置当前正在破解所用的盐值 |
| `set_key(key, idx)` | 向缓冲区写入第 idx 个候选密码 |
| `crypt_all(count, salt)` | 对所有候选密码执行加密/哈希运算 |
| `cmp_all(binary, count)` | 快速批量比较，返回是否有命中 |
| `cmp_one(binary, idx)` | 对单个候选密码做精确比较 |
| `cmp_exact(source, idx)` | 最终完整验证（可选，用于降低误报） |

### 1.2 破解流程

```
候选密码 ──set_key()──► [密码缓冲区]
                              │
                        crypt_all()  ← set_salt()
                              │
                         [摘要缓冲区]
                              │
                     cmp_all() / cmp_one()
                              │
                    命中? ──► cmp_exact() ──► 输出明文
```

### 1.3 支持的破解模式

- **单破解模式（Single）**：利用账户名、GECOS 字段等信息结合规则生成候选密码，速度最快。
- **单词表模式（Wordlist）**：从字典文件中逐行读取候选密码，可配合规则变形。
- **增量模式（Incremental）**：穷举指定字符集和长度范围内的所有组合，最彻底但最慢。
- **掩码模式（Mask）**：按位置指定字符集，适合已知部分密码结构的场景。
- **Markov 模式**：基于字符概率统计模型生成候选密码。

---

## 二、压缩包破解原理

JtR 对 ZIP、RAR、7z 三种主流压缩包格式的破解采用相同的两阶段流程：

```
压缩包文件
    │
    ▼
[阶段一：哈希提取]  xxx2john 工具
    │  从压缩包头部读取加密参数（盐、校验值、密文数据等）
    │  输出为 JtR 可识别的文本格式散列行
    ▼
哈希文本文件
    │
    ▼
[阶段二：密码恢复]  john 主程序
    │  逐一生成候选密码 → 执行密钥派生 → 比较校验值
    │  若校验通过 → 用完整密文最终验证
    ▼
恢复的密码
```

---

### 2.1 ZIP 格式破解

ZIP 加密有两种独立实现：

#### 2.1.1 传统 PKZIP 加密（`$pkzip$`）

**加密算法：** PKZIP 流密码（基于 CRC-32 的三密钥流密码）

**密钥初始化（Key Schedule）：**

以下初始值为 PKZIP 规范中规定的固定常量（见 `src/pkzip_fmt_plug.c` 第 1141 行）：

```
key0 = 0x12345678
key1 = 0x23456789
key2 = 0x34567890

对密码中每个字节 c：
    key0 = CRC32(key0, c)
    key1 = (key1 + low8(key0)) * 134775813 + 1
    key2 = CRC32(key2, high8(key1))
```

**解密字节流（Keystream）：**

完整公式（见 `src/pkzip_fmt_plug.c` 中 `PKZ_MULT` 宏/内联函数）：

```c
// 完整计算：
t = (key2.u | 2)          // key2 低16位强制设置 bit1
decrypt_byte = (t * (t ^ 1)) >> 8   // 取高字节作为密钥流字节

// 化简写法（等价）：
decrypt_byte = mult_tab[(uint16_t)(key2.u) >> 2]  // 查表版本

// 解密一字节并更新密钥：
plaintext = ciphertext XOR decrypt_byte
key0 = CRC32(key0, plaintext)
key1 = (key1 + low8(key0)) * 134775813 + 1
key2 = CRC32(key2, high8(key1))
```

**破解过程（`pkzip_fmt_plug.c: crypt_all()`）：**

1. 将候选密码初始化为三个密钥 `key0/key1/key2`。
2. 用 12 字节随机 IV（前 10 字节随机，最后 2 字节为校验值）进行试解密。
3. 比较最后 1~2 个解密字节与文件头中存储的校验值（CRC 高字节或时间戳字节）。
4. 通过快速校验的候选密码进一步解密部分压缩数据，执行 INFLATE 语法检查。
5. 最终通过 CRC-32 对全文解压结果与存储的 CRC 比对来做完全验证（`cmp_exact()`）。

#### 2.1.2 WinZip AES 加密（`$zip2$`）

**加密算法：** PBKDF2-HMAC-SHA1 密钥派生 + AES-CTR 加密 + HMAC-SHA1 认证

**破解过程（`zip_fmt_plug.c`）：**

1. 从哈希行中提取：盐（8/12/16 字节）、2 字节密码验证值 `passverify`、HMAC-SHA1 认证码。
2. 对候选密码执行：
   ```
   PBKDF2-HMAC-SHA1(password, salt, iterations=1000, keylen=key_len+2)
   ```
   派生出加密密钥、HMAC 密钥以及 2 字节验证值。
3. **快速验证**：比较派生的 2 字节验证值与存储的 `passverify`，不匹配则立即淘汰（误报率约 1/65536）。
4. **完整验证（`cmp_exact()`）**：用派生的 HMAC 密钥对密文计算 HMAC-SHA1，与存储的认证码比对。

---

### 2.2 RAR3 格式破解（`$RAR3$`）

**加密算法：** SHA-1 密钥派生 + AES-128-CBC 加密

**密钥派生（`rar_fmt_plug.c: crypt_all()`）：**

```
RawPsw = Unicode(password) || salt   (其中 salt 为 8 字节)
对 i = 0..262143（共 262144 次）：
    SHA1_Update(ctx, RawPsw)
    每 16384 次更新时提取 1 字节 IV

SHA1_Final → AES 密钥
最后 16384 次每轮末尾的摘要字节拼接为 AES IV
```

**破解过程：**

1. 以上密钥派生计算量极大（262144 次 SHA-1 更新），因此 RAR3 破解速度很慢。
2. 支持 SIMD（SSE2/AVX2）并行计算多个 SHA-1 实例（`NBKEYS = SIMD_COEF_32 * SIMD_PARA_SHA1`）。
3. 对于 `-hp` 模式（头部加密），解密档案头后检查魔数；对于 `-p` 模式（文件加密），解密文件数据后验证 CRC-32。

---

### 2.3 7-Zip 格式破解（`7z`）

**加密算法：** SHA-256 密钥派生（可配置迭代次数）+ AES-256-CBC 加密

**密钥派生（`7z_fmt_plug.c: derive_key()`）：**

```
对 i = 0..(1 << NumCyclesPower) - 1：
    SHA256_Update(ctx, salt || password || little_endian_64(i))

SHA256_Final → AES-256 密钥
```

**破解过程：**

1. 从 `$7z$` 哈希行中解析：盐大小、NumCyclesPower（决定迭代次数）、IV、加密数据。
2. 执行 SHA-256 密钥派生，派生次数为 `2^NumCyclesPower`（默认约 524288 次），可通过 `NumCyclesPower` 字段调节强度。
3. 用派生密钥 AES-256-CBC 解密数据，然后执行 zlib/LZMA 解压，通过 CRC-32 验证解压结果。
4. 同样支持 SIMD 并行 SHA-256（`NBKEYS = SIMD_COEF_32 * SIMD_PARA_SHA256`）。

---

## 三、各格式破解难度对比

| 格式 | 密钥派生算法 | 迭代次数（约） | 相对速度 | 核心文件 |
|------|------------|-------------|---------|---------|
| PKZIP（传统） | CRC-32 流密码 | 密码长度次 | 极快 | `pkzip_fmt_plug.c` |
| ZIP AES | PBKDF2-SHA1 | 1,000 | 快 | `zip_fmt_plug.c` |
| RAR3 | SHA-1 | 262,144 | 慢 | `rar_fmt_plug.c` |
| 7-Zip | SHA-256 | ≥ 524,288 | 极慢 | `7z_fmt_plug.c` |

---

## 四、使用示例

```bash
# ZIP 文件
run/zip2john secret.zip > zip.hash
run/john zip.hash

# RAR 文件
run/rar2john secret.rar > rar.hash
run/john rar.hash

# 7-Zip 文件
run/7z2john.pl secret.7z > 7z.hash
run/john 7z.hash

# 使用字典加规则
run/john --wordlist=password.lst --rules zip.hash

# 使用增量模式（穷举）
run/john --incremental zip.hash
```

---

## 五、相关源码索引

| 文件 | 功能 |
|------|------|
| `src/john.c` | 主程序入口，破解模式调度 |
| `src/cracker.c` | 破解引擎核心循环 |
| `src/formats.c` / `formats.h` | 格式插件注册与管理 |
| `src/loader.c` | 散列文件加载与数据库构建 |
| `src/zip2john.c` | ZIP 哈希提取工具 |
| `src/pkzip_fmt_plug.c` | 传统 PKZIP 格式破解插件 |
| `src/zip_fmt_plug.c` | WinZip AES 格式破解插件 |
| `src/rar2john.c` | RAR 哈希提取工具 |
| `src/rar_fmt_plug.c` | RAR3 格式破解插件 |
| `src/7z_fmt_plug.c` | 7-Zip 格式破解插件 |
| `src/pkzip.c` / `pkzip.h` | PKZIP 流密码实现与数据结构 |
| `run/7z2john.pl` | 7-Zip 哈希提取脚本 |

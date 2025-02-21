# Immutable File Store

This project is a proof of concept implementation of the immutable file storage system described in the article [An immutable file and data store](https://medium.com/swlh/an-immutable-file-and-data-store-36f67fc044d7) by Craig Wright. The implementation demonstrates the core concepts of storing and sharing files on the Bitcoin SV blockchain using deterministic key generation and secure channels.

[中文版本](#immutable-file-store-中文版)

## Features

- Store files immutably on the Bitcoin SV blockchain
- Deterministic key generation for file encryption
- Secure file sharing between users
- Support for both testnet and mainnet
- Automatic transaction retry mechanism
- File metadata indexing

## Installation

1. Clone the repository:
```bash
git clone git@github.com:bitfs-org/immutable-file-store.git
cd immutable-file-store
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Store a File

```bash
python immutable_file_store.py put --file path/to/your/file.txt
```

### Retrieve a File

```bash
python immutable_file_store.py get --hash <file-hash> --save_path . --save_name retrieved_file.txt
```

### List Stored Files

```bash
python immutable_file_store.py list
```

### Share a File

```bash
python immutable_file_store.py share --hash <file-hash> --recipient <recipient-public-key>
```

### Receive a Shared File

```bash
python immutable_file_store.py receive --share-tx <share-transaction-id> --sender <sender-public-key>
```

## Testing

Run the test suite:

```bash
python -m unittest discover -v
```

## Directory Structure

- `immutable_file_store.py`: Main implementation file
- `secure_channel.py`: Secure communication channel implementation
- `test_immutable_file_store.py`: Test suite for file store
- `test_secure_channel.py`: Test suite for secure channel
- `private/`: Directory for private keys (gitignored)
- `test_data/`: Directory for test files and data (gitignored)

## Security

- Private keys are stored in the `private` directory
- All files are encrypted before being stored on the blockchain
- Secure communication channel uses ECDH for key exchange
- File sharing uses end-to-end encryption

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

# Immutable File Store (中文版)

本项目是对 Craig Wright 发表的文章 [An immutable file and data store](https://medium.com/swlh/an-immutable-file-and-data-store-36f67fc044d7) 中描述的不可变文件存储系统的概念验证实现。该实现演示了使用确定性密钥生成和安全通道在比特币 SV 区块链上存储和共享文件的核心概念。

## 特性

- 在比特币 SV 区块链上不可变地存储文件
- 用于文件加密的确定性密钥生成
- 用户之间的安全文件共享
- 支持测试网和主网
- 自动交易重试机制
- 文件元数据索引

## 安装

1. 克隆仓库：
```bash
git clone git@github.com:bitfs-org/immutable-file-store.git
cd immutable-file-store
```

2. 创建并激活虚拟环境：
```bash
python -m venv .venv
source .venv/bin/activate  # Windows 系统：.venv\Scripts\activate
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用方法

### 存储文件

```bash
python immutable_file_store.py put --file 文件路径/your/file.txt
```

### 获取文件

```bash
python immutable_file_store.py get --hash <文件哈希> --save_path . --save_name 已下载文件.txt
```

### 列出已存储的文件

```bash
python immutable_file_store.py list
```

### 分享文件

```bash
python immutable_file_store.py share --hash <文件哈希> --recipient <接收者公钥>
```

### 接收共享文件

```bash
python immutable_file_store.py receive --share-tx <共享交易ID> --sender <发送者公钥>
```

## 测试

运行测试套件：

```bash
python -m unittest discover -v
```

## 目录结构

- `immutable_file_store.py`: 主要实现文件
- `secure_channel.py`: 安全通信通道实现
- `test_immutable_file_store.py`: 文件存储测试套件
- `test_secure_channel.py`: 安全通道测试套件
- `private/`: 私钥目录（已加入 gitignore）
- `test_data/`: 测试文件和数据目录（已加入 gitignore）

## 安全性

- 私钥存储在 `private` 目录中
- 所有文件在存储到区块链之前都会被加密
- 安全通信通道使用 ECDH 进行密钥交换
- 文件共享使用端到端加密

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。 
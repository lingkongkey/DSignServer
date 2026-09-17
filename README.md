# DSign_server

本地 RFC3161 时间戳服务（TSA），单文件 C++ 实现，**同一份源码支持 Windows 和 Linux**。
同时支持两种时间戳协议（按请求体自动识别，均走 8080 端口根路径）：

- **RFC3161**（`application/timestamp-query`，signtool `/tr`）
- **Legacy PKCS#7 会签**（老版协议，signtool `/t`）

时间戳时间不使用系统时钟，而是从可执行文件同目录的 `HookSigntool.ini` 读取伪造时间，两种协议共用同一时间源。

## 目录说明

| 文件 | 说明 | 是否包含在仓库 |
|---|---|---|
| `server.cpp` | 服务端全部源码（双平台） | ✅ |
| `Makefile` | Linux 编译脚本 | ✅ |
| `*.sln` / `*.vcxproj` | Visual Studio 工程（Windows） | ✅ |
| `hook.cpp` / `hook.h` / `nmd_assembly.h` | Windows 内联 hook（仅 Windows 编译用） | ✅ |
| `HookSigntool/` | 配套 HookSigntool DLL 源码 | ✅ |
| `tsa.crt` / `tsa_ca.crt` / `tsa_legacy.crt` | 公开证书（TSA 叶子证书 + 根 CA + 旧版会签证书） | ✅ |
| **`tsa.key` / `tsa_legacy.key`** | **私钥** | ❌ 不上传，需按下文自行生成 |
| `HookSigntool.ini` | 伪造时间配置 | ❌ 首次运行自动生成默认值 |

## 编译

### Linux

```bash
# Debian/Ubuntu
sudo apt install g++ make libssl-dev
# CentOS/RHEL/Alibaba Cloud Linux
sudo yum install gcc-c++ make openssl-devel

make
./DSign_server
```

### Windows

用 Visual Studio 打开 `DSign_server.sln`，选择 **Release / Win32** 编译（依赖 OpenSSL 头文件和静态库）。
注意：`Release|x64` 配置的 OpenSSL 库路径指向了 x86 目录，请勿使用。

## 自行生成证书（重要）

仓库只包含证书，**不包含私钥**。clone 后需要自行生成一套 CA / TSA 证书，共产生 5 个运行所需文件。
需要 OpenSSL **1.1.1 或更高版本**（用到 `-not_before` / `-not_after`）。

> ⚠️ **证书 notBefore 必须早于伪造签名时间（默认配置为 2018-10-06）**。
> 如果用默认的 `-days` 从当天签发，证书生效时间晚于时间戳时间，Windows 验证会报 `0x80096005`。
> 下列命令已把起始时间固定为 2017/2018 年。

在 Linux 终端或 Windows 的 **Git Bash** 中执行：

```bash
mkdir certgen && cd certgen
export MSYS2_ARG_CONV_EXCL='*'   # 仅 Git Bash 需要，Linux 下无害

# ---------- 1. 根 CA（自签名）----------
openssl genrsa -out ca.key 2048
openssl req -new -key ca.key -out ca.csr \
  -subj "/C=CN/O=LocalTest/CN=Local Test TSA Root CA"
cat > ca.ext <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
EOF
openssl x509 -req -in ca.csr -signkey ca.key -out tsa_ca.crt \
  -extfile ca.ext -sha256 \
  -not_before 20170101000000Z -not_after 20371231235959Z

# ---------- 2. RFC3161 TSA 证书（必须含 timeStamping EKU）----------
openssl genrsa -out tsa.key 2048
openssl req -new -key tsa.key -out tsa.csr \
  -subj "/C=CN/O=LocalTest/CN=Local Test Timestamp Authority"
cat > tsa.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in tsa.csr -CA tsa_ca.crt -CAkey ca.key -CAcreateserial \
  -out tsa.crt -extfile tsa.ext -sha256 \
  -not_before 20180101000000Z -not_after 20371231235959Z

# ---------- 3. 旧版会签证书（无 EKU）----------
openssl genrsa -out tsa_legacy.key 2048
openssl req -new -key tsa_legacy.key -out tsa_legacy.csr \
  -subj "/C=CN/O=LocalTest/CN=Local Test Authenticode TSA"
cat > legacy.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl x509 -req -in tsa_legacy.csr -CA tsa_ca.crt -CAkey ca.key -CAcreateserial \
  -out tsa_legacy.crt -extfile legacy.ext -sha256 \
  -not_before 20180101000000Z -not_after 20371231235959Z
```

验证并部署到可执行文件同目录：

```bash
# 验证证书链
openssl verify -CAfile tsa_ca.crt tsa.crt tsa_legacy.crt
# 确认 RFC3161 EKU
openssl x509 -in tsa.crt -noout -ext extendedKeyUsage   # 应输出 Time Stamping

# 部署（ca.key 是根私钥，离线妥善保管，不要放到服务器上）
cp tsa_ca.crt tsa.crt tsa.key tsa_legacy.crt tsa_legacy.key /path/to/server/
chmod 600 tsa.key tsa_legacy.key
```

Windows 客户端信任测试用的根证书（管理员 CMD，在证书目录执行）：

```bat
certutil -addstore -f Root tsa_ca.crt
```

或直接运行仓库里的 `InstallTsaCa.bat`（会安装同目录的 `tsa_ca.crt`）。

## 运行

证书文件按**工作目录（CWD）**的相对路径加载，`HookSigntool.ini` 按**可执行文件所在目录**加载，
最简单的方式是所有文件放同一目录并在该目录启动：

```bash
./DSign_server
```

要求：

- 系统时区为 **Asia/Shanghai**（ini 存的是北京时间，Linux 可用 `TZ=Asia/Shanghai ./DSign_server` 临时指定）
- 防火墙 / 云安全组放行 **8080/TCP**
- 首次运行若没有 `HookSigntool.ini`，会自动生成默认配置（2018-10-06 20:05:50）

后台常驻：

```bash
nohup ./DSign_server > tsa_stdout.log 2>&1 &
```

systemd 开机自启（`/etc/systemd/system/dsign.service`）：

```ini
[Unit]
Description=DSign TSA Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/server
ExecStart=/path/to/server/DSign_server
Restart=always
RestartSec=3
Environment=TZ=Asia/Shanghai

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now dsign
```

## 客户端使用

服务不区分 URL 路径，按请求体自动识别协议，同一地址同时支持两种调用：

```bat
:: RFC3161（SHA256 时间戳）
signtool sign /fd sha256 /tr http://<服务器IP>:8080 /td sha256 ...

:: Legacy（SHA1 旧版会签）
signtool sign /t http://<服务器IP>:8080 ...
```

每次请求都会在工作目录的 `tsa_requests.log` 追加审计行（真实请求时间、协议、写入的伪造时间）。

## 安全提示

- `tsa.key`、`tsa_legacy.key`、`ca.key` 是私钥，任何持有者都能冒充本 TSA 签发时间戳，请勿提交到代码仓库或随意外发
- 本项目用于本地测试场景，默认使用自签名 CA，不要用于生产环境

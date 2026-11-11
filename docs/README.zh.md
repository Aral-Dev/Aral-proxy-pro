# ProxyGosha — 基于 Cloudflare Workers 的 Telegram WEB 代理

> 运行在 Cloudflare 免费配额上的 Telegram 私有代理。单文件、单一配置项，无需租用或维护任何服务器。

<p align="center">
  <a href="https://github.com/amirmarandidev/ProxyGosha/stargazers"><img src="https://img.shields.io/github/stars/amirmarandidev/ProxyGosha?style=for-the-badge&color=gold" alt="GitHub Stars"></a>
  <a href="https://workers.cloudflare.com/"><img src="https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare Workers"></a>
  <a href="https://desktop.telegram.org/"><img src="https://img.shields.io/badge/Telegram-WEB%20Proxy-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram WEB Proxy"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License MIT"></a>
</p>

<p align="center">
  <a href="../README.md"><b>English</b></a> •
  <a href="README.fa.md"><b>فارسی</b></a> •
  <a href="README.ru.md"><b>Русский</b></a> •
  <a href="README.zh.md"><b>简体中文</b></a> •
  <a href="llms.txt"><b>llms.txt</b></a>
</p>

---

## 📺 视频安装配置教程

> [!TIP]
> 如果您更喜欢直观的视频演示，可以在 YouTube 上观看完整的分步配置指南：  
> ▶️ **[在 YouTube 上观看视频教程](https://youtu.be/7StSCQdpqvk)** *(附带清晰明了的屏幕操作演示)*

<p align="center">
  <a href="https://youtu.be/7StSCQdpqvk">
    <img src="https://img.youtube.com/vi/7StSCQdpqvk/maxresdefault.jpg" alt="ProxyGosha 视频教程" width="700">
  </a>
</p>

<p align="center">
  <a href="https://t.me/amirdotlog"><img src="https://img.shields.io/badge/Telegram-amirdotlog-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram Channel"></a>
  <a href="https://www.youtube.com/@amirmarandidev"><img src="https://img.shields.io/badge/YouTube-amirmarandidev-red?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube Channel"></a>
</p>

> [!NOTE]
> 📢 **Telegram 官方频道：** 获取纯净可用域名、最新更新公告与搭建技巧：**[t.me/amirdotlog](https://t.me/amirdotlog)**  
> 🔴 **YouTube 视频频道：** 订阅获取更多视频教程与抗审查技术解析：**[youtube.com/@amirmarandidev](https://www.youtube.com/@amirmarandidev)**

---

## 🚀 v1.2.2 版本更新内容

本次更新带来了重大的连接可靠性改进、底层传输协议优化以及内置状态诊断功能：

- 🛠️ **修复连接问题与提升稳定性：** 解决了超时导致的套接字泄漏 (Socket leak)，剔除无效的测试 DC 端点，全面更新 Telegram 官方数据中心 IP 列表。
- ⚡ **上行数据合并优化 (Upstream Batching)：** 将客户端发送的零散小数据帧在上行前合并批量处理，显著减少 WebCrypto 繁琐加解密开销，大幅降低 Worker 实例的 CPU 占用。
- 📊 **实时监控与诊断仪表盘 (特别鸣谢 EmadReza)：** 新增 `/<ADMIN_KEY>/status` 管理页，提供活跃会话数、流量吞吐、实例运行时间统计，并支持一键发起 Telegram 数据中心 (DC1–DC5) 连通性与延迟探测 (DC Probe)。

---

## 这是什么

Telegram 推出了一种名为 **WEB** 的新型代理协议。与传统的 MTProto 代理不同，它的流量形态与普通的 HTTPS 流量完全一致，因此可以顺畅运行在 Cloudflare 之后。

ProxyGosha 正是将一个免费的 Cloudflare Worker 变成这样一个私有代理。

**通俗浅显的解释：** Cloudflare 拥有极其庞大的全球 Anycast 边缘网络，当今互联网很大一部分正常网站都在该网络后运行，因此审查防火墙全面封锁 Cloudflare 的成本极其高昂。您的 Worker 是运行在这个庞大网络内部的一个微型程序。Telegram 客户端与您的 Worker 通信，Worker 再将流量安全中继转发至 Telegram 官方服务器。

- **外观完全是一个正常网站。** 任何人用普通浏览器直接访问您的地址，看到的都是一家制作精美的服装在线商城。
- **无法解密或窥探您的聊天内容。** Telegram 客户端与官方服务器之间全程采用端到端强加密。代理仅负责承载这些密文字节流。
- **零运行成本。** 完全依赖 Cloudflare 提供的免费配额运作。唯一的可选开销是一个属于自己的域名（通常每年只需几美元）。

---

## 准备工作

您需要：

1. **一个 Cloudflare 账号。** 完全免费。请前往 [dash.cloudflare.com](https://dash.cloudflare.com/) 注册。
2. **一个自定义域名（强烈推荐）。** 默认的 `workers.dev` 域名在部分地区（如伊朗等）已被防火墙阻断，且可能受限于部分端口。任何托管到 Cloudflare 的平价域名均可。
3. **支持 WEB 代理协议的 Telegram 客户端。** Telegram Desktop 电脑端已经原生内置该支持；手机端（安卓与 iOS）在客户端更新推送后即可获得该功能选项。

---

## 部署教程 — 仅需五步

### 第 1 步 — 创建 Worker

1. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)。
2. 进入导航栏 **Workers 和 Pages** → **创建应用程序** → **创建 Worker**。
3. 输入任意名称（例如 `my-tg-proxy`），点击 **部署**。

### 第 2 步 — 粘贴代码

1. 进入刚刚创建的 Worker 页面，点击 **编辑代码** (Edit code)。
2. 清空代码编辑器中的所有默认代码，将本项目的完整代码 [`worker.js`](../worker.js) 粘贴进去。
3. 点击 **部署**。

### 第 3 步 — 设置管理密钥（唯一必需的配置项）

1. 在浏览器中打开您的 Worker 域名。页面将呈现一个**设置引导页 (setup page)**，上面会自动生成一个随机密钥，将其复制。
2. 回到控制台进入该 Worker → **设置** (Settings) → **变量和机密** (Variables and Secrets) → **添加** (Add)：
   - **变量名称 (Name)：** `ADMIN_KEY`
   - **值 (Value)：** 刚刚复制的密钥（或者任何由至少 16 位英文字母及数字组成的强密码）
3. 点击 **部署** 保存。

> [!IMPORTANT]
> 请像保管密码一样妥善保管 `ADMIN_KEY`。任何掌握此密钥的人都可以打开您的管理面板并查看到代理密钥。

### 第 4 步 — 绑定自定义域名

1. 将您的域名托管到 Cloudflare。Cloudflare 会给出两个 DNS 名称服务器（NS 地址）。请前往您购买域名的服务商处将 DNS 服务器修改为 Cloudflare 指定的地址。
2. 在该 Worker 页面中，前往 **设置** → **域和路由** (Domains & Routes) → **添加** → **自定义域**。
3. 输入一个二级子域名，例如 `tg.yourdomain.com`。Cloudflare 将全自动完成 SSL 证书签发与 DNS 路由解析。

#### 🌐 域名选择与配置指南 (为什么必须绑定自定义域)

很多朋友询问是否必须准备自定义域名以及该如何获取：

> [!WARNING]
> 目前 Cloudflare 默认分配的 **`workers.dev`** 子域名在**伊朗**、**中国大陆**、**俄罗斯**等国家和地区的网络防火墙中普遍已被阻断或干扰。  
> 为了确保代理能够在所有网络运营商环境下稳定畅通，**必须为您的 Worker 绑定一个自定义独立域名。**

### 获取域名的常用途径：

- ☑️ **免费域名方案：**  
  您可以优先通过支持免费域名的平台（例如 **[digitalplat](https://domain.digitalplat.org/)**）申请免费域名，并免付费接入 Cloudflare 使用。
- ❇️ **国家顶级域名 (如伊朗 `.ir`、俄罗斯 `.ru` 等)：**  
  - 也可以使用各国家/地区本地域名。  
  - ⚠️ **安全注意：** 使用实名制国家域名时请保持谨慎，切勿用于违规高风险操作。  
  - 尽管国家后缀通常较为廉价，但实名认证与资质审核审核（如 [nic.ir](https://nic.ir/)）通常需要 **1–2 个工作日**。
- ‼️ **购买廉价国际域名 (支持数字货币或境外卡支付)：**  
  如果您具备外币卡或加密货币支付条件，可以通过 **[Namecheap](https://namecheap.com/)** 等国际注册商购买低价专属后缀（如 `.xyz`、`.top` 等，通常首年仅需几美分或 1 美元以下），即买即用非常方便。

### 第 5 步 — 打开管理面板并一键连接

在浏览器中打开：

```text
https://tg.yourdomain.com/YOUR_ADMIN_KEY
```

管理面板提供两种连接方式：

- **一键导入：** 面板针对全部六个端口分别提供了 **Connect in Telegram** 快捷按钮。在已安装 Telegram 的手机或电脑上点击即可秒级添加代理。
- **手动输入：** 提供了**服务器 (Server)** 以及面板中每个**端口 (Port)** 及其专属的**密钥 (Secret)**：

| 字段 | 内容 |
|---|---|
| 服务器 (Server) | `tg.yourdomain.com` |
| 端口 (Port) | `443` · `2053` · `2083` · `2087` · `2096` · `8443` 中的任意一个 |
| 密钥 (Secret) | 管理面板表格中对应端口的专属密钥 |

在 Telegram 客户端中的配置入口：

- **电脑端 (Desktop)：** 设置 → 高级 → 连接类型 → 使用自定义代理 → 添加代理 → **WEB**
- **移动端 (Mobile)：** 设置 → 数据和存储 → 代理 → 添加代理 → **WEB**（客户端更新支持后可见）

**配置完成。** 如需与家人朋友分享代理，请仅发送**连接链接或连接参数（服务器、端口及该端口对应的密钥）**。切勿将您的管理面板网址分享给他人。

### 实时监控与连接诊断 (Status & Logs)

如需确认代理运行状态、查看实时流量统计以及诊断 Telegram 数据中心连接：

```text
https://tg.yourdomain.com/YOUR_ADMIN_KEY/status
```

- **实时统计：** 活跃会话数、打开的数据流、上下行流量统计以及 Worker 实例运行时间。
- **数据中心探测 (DC Probe)：** 从 Cloudflare 边缘节点直接测试到 Telegram 各数据中心 (DC1–DC5) 的连通性与延迟（毫秒）。
- **隐私保护：** 所有指标和事件日志仅保存在临时内存中，实例重置即清空；绝不记录任何用户 IP、令牌或密钥。

---

## 端口支持

Cloudflare 旗下的全部六个 HTTPS 安全端口均开箱即用，无需任何额外设置：

`443` · `2053` · `2083` · `2087` · `2096` · `8443`

为了隔离不同连接并防止互相干扰，每个端口均拥有独立专属的连接密钥（由系统自动派生生成）。如果某个端口遇到本地网络干扰或减速，只需切换至另一个端口并填入面板中该端口对应的密钥即可。您可以在 Telegram 中添加多次同一代理并配置不同端口，随时自由切换。

---

## 环境变量配置参考

只有 `ADMIN_KEY` 是必须配置的。其余所有环境变量均为可选。

| 环境变量 | 作用说明 |
|---|---|
| `ADMIN_KEY` | **必需。** 管理面板的访问密码。代理的各端口连接密钥由此密钥派生生成。 |
| `SECRET` | 固定的 32 位十六进制密钥（用于 443 端口并作为其它端口派生的基准）。如果您希望日后更改 `ADMIN_KEY` 而不影响已分享出去的代理链接，请配置此项。 |
| `EXTRA_HOSTS` | 绑定至该 Worker 的其它域名，以英文逗号分隔。面板会同步为这些域名生成连接信息。 |
| `DECOY_URL` | 真实网站地址，用于替代内置的服装店伪装页展示给常规访客。这可以使您的代理特征更具隐蔽性。 |
| `CARRIER` | 留空即可。仅当默认传输模式存在网络异常时，才需要指定为 `websocket`。 |

> [!WARNING]
> 如果未配置 `SECRET`，更改 `ADMIN_KEY` 将同时改变派生生成的代理密钥，**所有之前分享出去的代理链接将全部失效。**

---

## 强封锁环境抗干扰指南

请按以下顺序排查优化：

1. **切换端口。** 换用上面列出的其它 Cloudflare 备用安全端口。
2. **换用备用域名。** 若某个域名遭受阻断，将另一个备用域名绑定到该 Worker，并将其加入环境变量 `EXTRA_HOSTS`。
3. **使用 Cloudflare 优选 IP (Clean IP，仅限电脑端)。** 若域名默认解析到的 Anycast IP 被运营商阻断或劣化，可在本地系统 `hosts` 文件中将域名指向一个可用的 Clean IP：
   - Windows 路径：`C:\Windows\System32\drivers\etc\hosts`
   - macOS / Linux 路径：`/etc/hosts`

   ```text
   CLEAN_IP   tg.yourdomain.com
   ```

   将 `CLEAN_IP` 替换为在您当前宽带网络下经过测速可用的 Cloudflare IP。由于优选 IP 会随网络波动发生变化，请根据实际情况进行测试与更新。
4. **在阻断区域关闭 ECH（如针对俄罗斯等特殊网络策略）。** 在 Cloudflare 控制台中进入该域名页面 → **SSL/TLS** → **Edge Certificates** → **Encrypted Client Hello (ECH)** → **Off (关闭)**。

> [!NOTE]
> 在遭遇**全网物理性断网**（完全切断国际出口网络 / 仅限国内白名单网络）时，任何境外代理均无法工作。Cloudflare 的数据中心位于境外，国际出口阻断后任何 Cloudflare 流量都无法出境。上述策略适用于常规审查封锁、干扰和流量限制场景，而非应对全网断网状态。

---

## 故障排查

| 现象 | 解决方法 |
|---|---|
| 浏览器打开地址显示一家服装在线商城 | 完全正常。代理程序在其后静默运行。如需进入管理面板，请在网址末尾附加 `/YOUR_ADMIN_KEY`。 |
| 访问面板网址依然显示商城 | 网址中输入的密钥与环境变量 `ADMIN_KEY` 不匹配，或者设置变量后忘记点击 **部署** 保存。 |
| 重新出现设置引导页 (setup page) | 缺少环境变量 `ADMIN_KEY`，或者该密钥长度少于 16 个字符。 |
| Telegram 客户端一直显示“连接中” (connecting) | 尝试更换端口。然后测试其它域名。如果使用的是 `workers.dev`，请换成绑定的自定义域名。 |
| 原本可用的分享链接突然连不上了 | 在未配置固定 `SECRET` 的情况下修改了 `ADMIN_KEY`。请从面板中获取重新生成的新链接。 |

---

## 常见问题 (FAQ)

<details>
<summary><b>哪些 Telegram 客户端可以使用？</b></summary>
任何提供了 <b>WEB</b> 代理协议选项的 Telegram 客户端均可使用。Telegram Desktop 电脑端已经原生全面支持；Android 和 iOS 移动端在收到包含该特性的客户端更新后即可顺畅连接。
</details>

<details>
<summary><b>一个代理可以供多少人同时使用？</b></summary>
本项目为个人及小范围亲友圈日常使用量身打造。Cloudflare 免费套餐每个账号每天提供 100,000 次请求额度。如果使用者较多，建议每个小群体各自部署专属的 Worker，这样可以有效分散负载，避免单个链接泄露导致全体受限。
</details>

<details>
<summary><b>Cloudflare 或代理节点能窥探我的聊天记录吗？</b></summary>
无法窥探。Telegram 客户端与官方服务器之间的流量采用 MTProto 端到端加密保护。代理节点仅充当中继中转加密数据包的角色，没有任何私钥能够解密您的通信内容。
</details>

<details>
<summary><b>可以添加赞助频道标签（Ad Tag）吗？</b></summary>
不支持。Telegram 的频道推广赞助系统在握手时强制要求固定的外部出口端口。Cloudflare Workers 运行在无服务器共享 NAT 架构上，外部出口端口是动态随机分配的，无法支持该功能。代理直接与 Telegram 官方数据中心建立纯净连接，无广告且更加稳定快速。
</details>

---

## 免责声明

本项目仅供网络协议研究、计算机教学与个人测试使用。请注意，利用 Cloudflare Workers 搭建公开代理服务可能涉及违反 Cloudflare 服务条款（第 2.2.1(j) 条）。请仅限于个人合规学习研究，切勿用于非法用途。

---

## 项目支持

ProxyGosha 是一个免费开源项目。如果您觉得本项目对您有所帮助，欢迎在 GitHub 上点亮 ⭐，或者通过加密货币赞助支持项目的持续维护：

- **USDT (BEP20):** `0xd593ae9D32bEA690EC62460C54BF3951aFFF7803`
- **USDT (TRC20):** `THaaHzoTwXfUfcrtYTDXRsMmk9qhnXa56M`

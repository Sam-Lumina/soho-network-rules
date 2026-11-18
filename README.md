# SOHO Network Rules

SOHO Network Rules 为 Clash Verge Rev / Mihomo 和 Shadowrocket 提供一套通用分流规则。国内、Microsoft 和普通未知流量默认直连，指定国际业务与成人分类走代理，广告、博彩和已知威胁域名被拦截。节点和订阅由你在客户端单独管理，本项目只提供规则与配置。

## Stable 下载

以下地址提供 GitHub Pages 上的稳定配置。

- Windows · [mihomo-merge.yaml](https://sam-lumina.github.io/soho-network-rules/stable/mihomo-merge.yaml)
- iPhone · [shadowrocket.conf](https://sam-lumina.github.io/soho-network-rules/stable/shadowrocket.conf)

## Windows 快速安装

1. 保留原订阅。在 Clash Verge「订阅」创建一份单独的 Remote，使用你自己的订阅地址。自管节点也可存放在自己的 Local 配置。
2. 下载 Merge 文件，将完整内容粘贴到这份订阅的「编辑扩展配置」，保存并选中该订阅。这个文件需要绑定到已有节点的配置。
3. 在「代理」页的 **PROXY** 组选择可用节点，再从「规则」页刷新规则集。确认 32 个远程规则集及两个内联规则集均已加载后，用 Rule + TUN，系统代理关闭。临时切全局时继续使用同一个 PROXY。

Windows 已在 Clash Verge Rev 2.5.10 / Mihomo 1.19.33 上实机验证 Rule + TUN 和 Global + TUN，系统代理关闭。节点订阅按客户端设置更新，远程规则集每 24 小时检查。Merge 有新版时，可从同一地址下载并替换订阅扩展。联网异常时可选回原订阅。

已配置本机定时同步的设备可以定期检查 Merge。定时检查已运行，新版自动替换并生效仍待实测。本机同步需单独配置，公开安装流程使用 Clash Verge 的订阅扩展。

## Shadowrocket 快速安装

1. 在「首页」导入自己的节点或订阅，选择可用节点。
2. 在「配置」添加 Stable 配置地址，下载并选中。
3. 将「全局路由」设为「配置」。点配置文件名，再点「更新」，可手动刷新整份配置。

Shadowrocket 2.2.93 和 2.2.76 均已实机导入、选用和手动更新。两台验收设备均已在 Shadowrocket「设置 → 更新 → 配置」开启自动后台更新，间隔为 7 天，并允许 iOS 后台 App 刷新。首次后台自动更新尚待观察。

Windows 直接跟随 MetaCubeX 的国外 AI 和 Meta 分类更新，现有国内和 Microsoft 规则优先于这两个补充分类。Shadowrocket 直接订阅社区维护的 Facebook 和 Instagram 域名清单。两端在配置中保留 Muse 登录链路的已验证主机。

## 已知限制

已列入静态保护的关键域名在规则集缺失时仍匹配代理策略。初次下载失败时，只有动态规则覆盖的目标可能落入直连兜底。先确认规则集加载再使用。域名过滤只能拦截部分广告。DNS、IPv6 和 UDP 的实际表现取决于客户端、系统与节点。

Windows 验收中，国内外 DNS 样本均由 TUN 接管，直连和代理的 UDP 样本均有应答。部分强制 HTTP/3 样本未完成握手，普通 HTTPS 经 TCP 实测可用。验收网络未提供可用的公网 IPv6，双栈下的防绕过仍待验证。

## 社区分类对照

GitHub Actions 定期读取十个公开上游的分类目录并对比文件内容签名。对照表列出优先来源、已选走法、按默认策略处理的分类，以及需要判断的混合分类。相同分类中的相同文件和内容不同的文件分别标记。后续运行记录新增、删除和修改。客户端按设置刷新已接入的远程名单。

Netflix、Hulu、Spotify、Twitch 和 Formula 1 使用排名靠前的 MetaCubeX 分类。独立运营的 Hulu 日本版由 ACL4SSR 补齐。Windows 直接订阅原始名单。iPhone 的 MetaCubeX 流媒体清单由 Actions 定时转换发布，Hulu 日本版直接订阅上游。

成人类使用 MetaCubeX 的分类，博彩使用 HaGeZi 完整名单。两类名单交叉时先拦截。Windows 直接使用 MetaCubeX 成人分类，Shadowrocket 使用定时转换的同源清单。两个客户端共用转换后的博彩名单。分类过滤在客户端的规则模式生效。

两端共用扩展业务名单。Disney+、Prime Video、Apple TV+、HBO、Discord、TikTok、Perplexity、Hugging Face 等来自 MetaCubeX，走代理。国内银行、证券、教育、物流、网盘、社交，以及 Steam、Epic、任天堂等常规游戏服务走直连。ACL4SSR 补充 All4、ITV、My5、Pandora、Qobuz，走代理。精确分类见 [共同策略](rules/policy.json)，构建后的 MetaCubeX 名单每天检查上游并自动更新。普通未指定用途的类别继续按现有规则匹配，最后由直连兜底。

## 许可与反馈

原创内容中有权授权的部分采用 [PolyForm Noncommercial 1.0.0](LICENSE)。超出许可证允许范围的商业使用须取得相应权利人的书面授权，可通过 Issues 联系。第三方数据遵守其各自的 GPL、MIT 等许可。 [第三方声明](THIRD_PARTY_NOTICES.md)

规则误判与兼容问题请提交 [Issue](https://github.com/Sam-Lumina/soho-network-rules/issues)。 [贡献方式](CONTRIBUTING.md) · [安全报告](SECURITY.md)

## English

Routing rules for Mihomo / Clash Verge Rev and Shadowrocket. Bring your own nodes and keep them in your client. Windows Rule and Global modes were verified with TUN. Import and manual refresh were verified on Shadowrocket 2.2.93 and 2.2.76. Background refresh is configured and its first automatic run has yet to be observed. Original material is source available under PolyForm Noncommercial, and third-party data keeps its original terms.

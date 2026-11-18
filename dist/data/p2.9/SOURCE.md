# Corresponding source for rule data

The GPL-3.0 text is bundled in [LICENSE](LICENSE). The retained MIT texts and other upstream notices are bundled in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

- `tif-mini.mrs` is compiled from the published HaGeZi TIF Mini exact-domain list. The conversion changes representation and keeps exact-name matching. [Original source](https://raw.githubusercontent.com/hagezi/dns-blocklists/e681da879e1b4aaed4962170d0e278d6817542df/wildcard/tif.mini-onlydomains.txt) · [Upstream notices](https://github.com/hagezi/dns-blocklists/blob/e681da879e1b4aaed4962170d0e278d6817542df/README.md)
- `meta-ads.list` and `meta-international.list` convert published MetaCubeX MRS sets to Shadowrocket rule syntax. Plain names become DOMAIN matches, explicit suffixes become DOMAIN-SUFFIX matches, and duplicate records are removed. [Exact input URLs and SHA-256](SHA256.json) · [MetaCubeX GPL license](https://github.com/MetaCubeX/meta-rules-dat/blob/58212bb83ef4a06d36d754b3f98ac22f8ef61955/LICENSE)

The MetaCubeX build takes V2Fly domain data and builds it with Loyalsoldier domain-list-custom. The 848 advertising entries and 1,241 international entries were also checked against the relevant category files and their includes in a public V2Fly revision near the upstream build date. The V2Fly Google category attributes entries to the WTFPL-2.0 dnsmasq-china-list. [MetaCubeX build workflow](https://github.com/MetaCubeX/meta-rules-dat/blob/58212bb83ef4a06d36d754b3f98ac22f8ef61955/.github/workflows/run.yml) · [V2Fly comparison revision](https://github.com/v2fly/domain-list-community/tree/41504eae2a11f305fe88cfc605cf6c105a80bf5a/data) · [Google source file](https://github.com/felixonmars/dnsmasq-china-list/blob/94f89bb5065cdff0777ef3a116ecfecb14ca1f56/google.china.conf)

Reproduce from the source repository with Python 3.12 and Mihomo 1.19.33. Run `python tools/build_rule_data.py --mihomo mihomo --output dist/data/p2.9` from the project directory. Compare the outputs to the manifest. [GPL-licensed conversion script](https://github.com/Sam-Lumina/soho-network-rules/blob/main/tools/build_rule_data.py) · [Mihomo source for this converter version](https://github.com/MetaCubeX/mihomo/tree/v1.19.33)

Updating these snapshots requires a new reviewed data directory. Keep the old version accessible while old configuration files can still reference its URLs.

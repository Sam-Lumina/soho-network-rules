# Community rule data

`media.list` and `adult.list` convert the approved MetaCubeX categories from their native domain-list format for Shadowrocket, preserving exact and suffix matching. `gambling.list` converts the full HaGeZi Gambling wildcard list into native suffix rules for both clients. Domain suffix rules cover the listed host and its subdomains. The exact GitHub revisions, source URLs and checksums are recorded in [SHA256.json](SHA256.json).

`services-proxy.list` and `services-direct.list` combine the additional approved MetaCubeX categories for both clients. The lists keep the upstream domain matching and remove duplicate entries. Separately referenced ACL4SSR files remain hosted by ACL4SSR.

`telegram-ip.list` converts MetaCubeX's Telegram GeoIP list into IPv4 and IPv6 CIDR rules for both clients. Both main configurations also embed the ranges published by Telegram, an additional MetaCubeX range, and the exact supplementary endpoint confirmed in the application trace and the Repcz list. [Telegram ranges](https://core.telegram.org/resources/cidr.txt) · [Repcz Telegram rules](https://github.com/Repcz/Tool/blob/X/Loon/Rules/Telegram.list)

The converted data follows the same upstream GPL-3.0 and retained attribution as the project rule-data package. [GPL-3.0 text](../p2.9/LICENSE) · [Upstream copyright notices](../p2.9/THIRD_PARTY_NOTICES.md) · [HaGeZi Gambling and redistribution terms](https://github.com/hagezi/dns-blocklists) · [Conversion source](https://github.com/Sam-Lumina/soho-network-rules/blob/main/tools/build_community_data.py)

Reproduce the current approved selection with `python tools/build_community_data.py`. The selected categories are recorded in [policy.json](https://github.com/Sam-Lumina/soho-network-rules/blob/main/rules/policy.json).

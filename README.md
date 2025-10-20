# acme_script

项目包含两个脚本：
- acme.sh：通用型一键安装/管理 acme.sh 的证书申请脚本，支持多发行版、HTTP-01（standalone）与 Cloudflare DNS（含泛域名）、查看/撤销/续期/切换 CA 等。
- acmessl.sh：面向 Nginx 的一体化脚本，快速完成证书申请与 443 反向代理落地，适合将本地后端端口快速接入 HTTPS。

快速使用（acme.sh）：

```shell
wget -N --no-check-certificate https://raw.githubusercontent.com/CKBTester/acme_script/main/acme.sh && bash acme.sh
```

详细对比分析（优缺点与改进建议）：
- docs/acme_vs_acmessl_analysis_zh.md

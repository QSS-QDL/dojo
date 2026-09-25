# 08 · 中间件与 Web 服务器：谁在解析、谁在拦、缝隙在哪

> 现代架构至少两层（CDN/网关 → 中间件 → 应用），**每两层之间必有解析差异，差异即攻击面**
> （dojo 02_心智模型/06 的统一理论在这一层最肥）。本篇按组件给判定+经典配置缺陷+差异表。

---

## 一、nginx（遭遇率第一的反代/静态层）

### 【判定】`Server: nginx/x.y.z`（可改，半可信）· 404 页长相（`<center>nginx</center>` 极简风）· `nginx/` 报错前缀 · 响应头顺序特征。版本旧=不维护信号（05 篇报文即证据）。

### 【经典配置缺陷】（判定探针全部单请求只读）
```
① alias off-by-slash（目录穿越，配置错误第一名）：
   成因: location /files { alias /home/; }   ← location 无尾斜杠 + alias 有尾斜杠（或反之）
   探针: GET /files../  → 列出上级目录 = 成立；GET /files../etc/passwd 首行（无害文件证明）
   变体: /files..;/ /files%2f../ （编码与分号的归一化差异）
② merge_slashes 差异: // 与 / 在后端路由眼中不同 → 鉴权路径绕过（//admin 类探针）
③ location 匹配优先级陷阱: = > ^~ > ~ > 前缀——正则 location 与前缀 location 覆盖不一致时，
   敏感路径保护被更宽的正则短路（探测法: 对被保护路径试尾斜杠/大小写/编码变体）
④ proxy_pass 尾部斜杠语义: 带/不带导致路径拼接差异（../ 归一化时机不同）
⑤ 客户端 body 大小/超时配置: client_max_body_size 大 → 上传面；超时短 → 杀时间盲注（你的老熟人，
   dojo 02_心智模型/06 §五 信道战争）
```

### 【学习】本地起 nginx 故意写错 alias（十分钟），亲手打穿再修复——**配置缺陷类知识动手一次记一辈子**；智库 `nginx alias` · `off-by-slash`。

---

## 二、Apache httpd

### 【判定】`Server: Apache/2.4.xx (Ubuntu)` · 404 页长相 · `.htaccess` 存在（Apache 独有）· `mod_status` 路径。

### 【经典面】
```
① CVE-2021-41773 / CVE-2021-42013（2.4.49 / 2.4.50 路径穿越+CGI 开启时 RCE）：
   判定: 版本 2.4.49/2.4.50 → 探针 GET /icons/.%2e/%2e%2e/etc/passwd（41773）
        /cgi-bin/.%2e/%2e%2e/etc/passwd（CGI 面）；42013 是 41773 修复的绕过（%%32%65 类双编码）
   版本精确匹配才打探针——这是「版本判定值千金」的教科书案例
② mod_status（/server-status）: 未授权时白送全部请求 URL+客户端 IP+虚拟主机清单（情报金矿，只读）
③ .htaccess 上传面: 上传目录若在 AllowOverride All 范围 → .htaccess 重定义解析（AddType 让 .xxx 当 PHP 执行）
④ 多后缀解析历史面（AddHandler 配置错时 x.php.jpg 解析）——老配置仍在存量系统里活着
```

---

## 三、IIS（.NET 系/政务老系统）

### 【判定】`Server: Microsoft-IIS/8.5`（版本号=Windows 版本对照表：7↔2008R2、8.5↔2012R2、10↔2016+——**IIS 版本白送操作系统版本**）· `X-Powered-By: ASP.NET` · `asp.net` 报错格式。

### 【经典面】
```
① 短文件名枚举（CVE-2012-4774 类扫描法）: /*~1*/a.aspx 的 404/400 差异 → 逐字符还原 8.3 短名
   价值: 还原出 /admin/backup/2019 类隐藏目录名（信息收集级，无破坏）
② WebDAV PROPFIND（CVE-2017-7269, IIS 6.0）: ScStoragePathFromUrl 溢出——古董系统仍存活，
   判定=版本 6.0+WebDAV 开启（OPTIONS 响应含 PROPFIND）；只判定版本与面存在，exploit 属级4红线
③ 解析差异历史面: x.asp;.jpg（分号截断,老版本）· x.asp/x.jpg（目录解析）· %80 类 Unicode 归一化
④ .config 文件访问: web.config 若可被静态服务读到= jackpot（连接串/machineKey→ViewState 07 篇 §三）
   探针: /web.config 一发（404/403/200 三态）
```

---

## 四、Tomcat（Java 系默认容器，详见 03 篇 §四，此处补路径机制）

```
① 路径参数（分号）: /admin;foo=bar/ 与 /admin;/ ——Tomcat 剥离分号段，前置网关若不剥离=鉴权绕过
   （Shiro/Spring Security + Tomcat 组合的经典差异，dojo 02_心智模型/06 §二 ③层）
② PUT 写文件（CVE-2017-12615）: readonly=false 时 PUT /test.jsp/ （尾斜杠/空格绕过扩展名过滤）
   判定: OPTIONS 看 Allow 含 PUT → 试 PUT 一个 .txt 无害文件（写 txt 属最小证明，写完删除并报告）
③ AJP（8009 Ghostcat CVE-2020-1938）: 内网/SSRF 可达 8009 → 读 WEB-INF 配置 → 含文件包含则 RCE
④ manager/host-manager: 弱口令面（tomcat/tomcat 默认清单一次尝试）；进去=WAR 部署=RCE，
   证明到「登录成功」即停（01 篇 §16 不留后门同样适用：不部署 WAR）
⑤ conf/tomcat-users.xml 泄露路径（配置错误时静态可读）
```

---

## 五、负载均衡与专用设备（F5 / A10 / 国产负载均衡）

```
判定: route=/SERVERID= cookie（会话粘滞招牌）· Via 头 · 特定报错页
F5 BIG-IP: /mgmt/tm 管理接口（CVE-2020-5902 TMUI 未授权 RCE——判定=版本+路径存在，不打链）·
          iControl REST 特征 · BIG-IP 后面看到的「源站」可能还有一层
多实例效应（05 篇报文即证据 §2.1）: 盲注/OOB 结果在实例间不一致 → 先确认粘滞再判定「洞没了」
X-Forwarded-For 信任链: 负载均衡常无条件信任 XFF → 内网 IP 白名单类鉴权可被 XFF: 127.0.0.1 探针测试
          （只读探针，01 篇 §3 合规；生效=高危越权证据）
```

---

## 六、HTTP 请求走私（概念级——判定方法给全，实操纪律最严）

### 【原理一句话】前端（代理/LB）与后端对「一个请求在哪里结束」的理解不一致（Content-Length vs Transfer-Encoding 的优先级/解析差异），攻击者把一个请求「藏」在另一个请求的 body 里，让它作为**下一个请求**被后端执行——**受害者是其他用户**。

### 【判定（安全版）】
```
CL.TE 探测: 发送 Content-Length 大于实际 body + body 内含 "0\r\n\r\n" 收尾的请求，
            观察是否「响应挂起直到超时」或「下一个请求被截断」——用时间差判定，不注入实际内容
TE.CL / TE.TE 同构探测（变形 Transfer-Encoding 头: 大小写/空格/重复头/obfuscation 变体）
HTTP/2 下: H2.CL / H2.TE（降级路径差异，PortSwigger 研究领域）
```

### 【红线（本篇最重）】走私的验证天然影响**共享连接上的其他用户**——
1. 只在授权明确覆盖+低峰窗口+单次探测级执行；
2. **不做**「走私完整请求窃取他人响应」的实战验证（时间差判定已足够证明存在性）；
3. 报告用「存在 CL/TE 解析分歧，可升级为请求走私（未执行跨用户验证）」表述。

### 【学习】PortSwigger 走私 lab 全通（它的实验环境是隔离的，随便打）；智库 `request smuggling`（概念篇）；这是 09 篇 WAF 绕过的深水区前置知识。

---

## 七、路径归一化差异总表（跨组件通用弹药，鉴权绕过的主力机制）

同一个「被保护路径」的变体探针组（每变体一发，观察 302/403 → 200 的翻转）：

| 变体 | 利用的差异 | 常见生效组合 |
|---|---|---|
| `/admin/`（尾斜杠） | 路由匹配精确性 | Spring/Nginx |
| `//admin` `///admin` | merge_slashes / 归一化次序 | Nginx+后端 |
| `/admin/.` `/admin/./x` | 点段归一化时机 | 网关不化简、后端化简 |
| `/..;/admin` `/admin;` | **Tomcat 分号剥离** | 前置网关+Tomcat（Shiro 组合经典） |
| `/%2e/admin` `/%2e%2e/` | URL 解码时机（先路由后解码 vs 反之） | 各类 |
| `/ADMIN` `/AdMiN` | 大小写敏感性差异（Windows 后端不敏感、Linux 网关敏感） | IIS/Windows |
| `/admin%20` `/admin%09` | 尾部空白截断 | 老版本各件 |
| `/admin\` `/admin%5c` | 反斜杠归一化 | Windows 系 |
| `/admin.json` `/admin.html` | 后缀匹配规则（框架把 .json 当同一路由） | Spring/Struts |
| `/admin/../admin` | 双归一化 | 多层代理 |

**使用方法**：对「403/302 的保护路径」机械过一遍这 10 变体（10 发请求，2 分钟）——这是 dojo 03 假设驱动的「标准化探针组」，命中率在国产网关+Tomcat 组合上相当可观（各家网关对 RFC 3986 的实现差异是长期存在的现实）。

---

## 【本篇学习建议】

1. **§七 归一化总表是全书最高频复用资产**——把它固化成脚本（对你的 unauth_enum/绕过测试都是现成弹药），并在 vault `MOC-现代防护对抗` 建「路径差异实测记录」（哪个变体在哪种组合上生效过）。
2. 学习顺序：§一 nginx（本地错配实验）→ §四 Tomcat（与 03 篇 Java 生态联动）→ §七 总表（脚本化）→ §六 走私（PortSwigger lab）→ §二三五按需。
3. 版本判定驱动一切：Apache 2.4.49、IIS 6.0、Tomcat PUT——**「版本号→CVE→探针」的反射弧**比记 CVE 本身重要（dojo 04 补丁 diff 流水线的情报源）。
4. 中间件层的洞多数是「配置错」而非「代码洞」——报告修复建议要写到配置行（`alias` 尾斜杠怎么改、`merge_slashes` 开不开），这是你报告专业度的又一次展示位。

## 【验收标准】

- [ ] §七 十变体能默写并各说一句利用的差异层
- [ ] 本地完成 nginx alias 错配实验（打穿+修复）
- [ ] IIS 版本→Windows 版本对照能秒答（7/8.5/10 三个）
- [ ] 能讲清 CL.TE 走私的「受害者是谁」以及为什么验证必须克制
- [ ] 路径变体探针组已脚本化进 cnvd-lab/tools/

## 【智库检索词】

`nginx alias` · `off-by-slash` · `41773` · `server-status` · `iis shortname` · `ghostcat` · `PUT 12615` · `request smuggling` · `path normalization` · `semicolon tomcat`

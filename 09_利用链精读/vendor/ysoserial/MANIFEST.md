# vendor/ysoserial · 拉取清单

> 来源：https://github.com/frohoff/ysoserial · 许可：**MIT**（LICENSE.txt 全文已随附）· 拉取日：2026-09-25
> 学术声明：DISCLAIMER.txt 原文随附——「purely for the purposes of academic research and for the development of effective defensive techniques」。
> 本目录用途：`09_利用链精读/02_Java利用链精读.md` 的配套源码教材，**仅供本地靶场学习研究**。

## 文件清单（精选 6 链 + 3 工具类，每个 .java 首行有溯源注释）

| 文件 | 内容 | 配套精读章节 |
|---|---|---|
| `payloads/URLDNS.java` | 无害 DNS 探测链（证明级标准） | 02 篇 §一（逐行精读主教材） |
| `payloads/CommonsCollections1.java` | CC1（LazyMap+AnnotationIH，历史起点） | 02 篇 §二 |
| `payloads/CommonsCollections5.java` | CC5（BadAttributeValueExpException 触发） | 02 篇 §二 |
| `payloads/CommonsCollections6.java` | CC6（HashSet 触发，全版本通杀） | 02 篇 §二（精读重点） |
| `payloads/Jdk7u21.java` | 纯 JDK 链（AnnotationIH+Templates 组合） | 02 篇 §三 |
| `payloads/Groovy1.java` | Groovy 生态链（MethodClosure 触发） | 02 篇 §九（触发环多样性样本） |
| `util/Gadgets.java` | TemplatesImpl 字节码构造等公共工具 | 02 篇 §三 |
| `util/Reflections.java` | setFieldValue 反射工具（链构造的万能手） | 02 篇 §九 |
| `util/ObjectPayload.java` | payload 接口定义 | — |

完整版（30+ 链）：上游仓库 `git clone https://github.com/frohoff/ysoserial`（只 clone 到本地学习环境，不再入库——反囤积纪律）。

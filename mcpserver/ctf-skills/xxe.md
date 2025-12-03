### 一、 XXE 题目的主要类型

#### 1. 经典回显型本地文件读取 (Classic In-Band LFI via XXE)

攻击者通过定义和调用外部实体，使服务器将本地文件内容作为 XML 响应的一部分返回，从而直接获取文件内容。

| 类型特征 | 详细描述 |
| :--- | :--- |
| **识别 XML 端点** | 攻击者尝试向特定端点（如 `/soap_service`）发送 `Content-Type: application/xml` 的请求。 |
| **利用目标文件读取** | 构造 DTD 实体，使用 `file:///` 协议引用本地敏感文件，例如：`<!ENTITY xxe SYSTEM "file:///etc/passwd">`。 |

#### 2. 通过文件格式触发的 XXE (XXE via File Format Exploitation)

应用程序接受基于 XML 的文件格式（如 SVG、DOCX 或其他自定义的 XML 文档）作为输入，从而触发解析漏洞。

| 类型特征 | 详细描述 |
| :--- | :--- |
| **SVG 上传利用** | 攻击者尝试通过 `POST` 请求上传一个 MIME 类型为 `image/svg+xml` 的 SVG 文件，该文件中嵌入了恶意的 DTD 载荷。SVG 文件本质上是 XML 格式，因此是利用 XXE 的常见载体。 |

#### 3. 间接文件协议利用（LFI 侧信道或利用 URL 处理器）

此类型中，应用程序可能不是直接处理 XML，但其内部组件（如 URL 解析器或文件恢复功能）允许 `file://` 协议的使用，本质上是利用了与 XXE 相同的文件读取能力。

| 类型特征 | 详细描述 |
| :--- | :--- |
| **URL 参数中的文件路径** | 在部分插件或应用中，攻击者在 URL 参数中直接注入 `bm_url=file:///opt/flag.txt`，试图通过这种机制读取本地文件。 |

#### 4. 高级 XML 上下文利用 (XPath/XSLT/Blind XXE)

当服务器不直接回显实体内容（无回显 XXE，Blind XXE）时，或在可以执行表达式的环境中，需要更复杂的技巧来提取数据。

| 类型特征 | 详细描述 |
| :--- | :--- |
| **XPath 注入实现文件读取** | 在 Struts 等使用 Java OGNL/EL 表达式的环境中，攻击者尝试利用 **XPath 表达式**来读取本地文件内容：`@javax.xml.xpath.XPathFactory@newInstance().newXPath().evaluate('string(/)', new org.xml.sax.InputSource('file:/tmp/flag'))`。这是一种利用 XML 解析上下文进行数据提取的**高级技巧**。 |

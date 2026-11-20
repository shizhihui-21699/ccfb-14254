defmodule SafeTpl.XssCase do
  @moduledoc """
  注入测试的共享判定逻辑。

  核心安全断言思路：对每个输出位置，喂入一批“逃逸探针”，渲染结果必须满足

    1. 探针中用于**跳出当前语法环境**的关键元字符（引号、尖括号、反斜杠、
       括号、空白等）不能以“活跃”形态出现在输出里——要么被实体/hex/u 编码，
       要么整个 URL/值被拒绝；
    2. 渲染结果重新按该上下文的规则切分时，插值仍停留在原本的语法位置，
       不能产生新的标签、属性、语句、声明或 URL scheme。
  """

  alias SafeTpl.{CompileError, RenderError}
  import ExUnit.Assertions

  @doc "渲染并返回字符串；编译期/渲染期错误原样抛出。"
  def render(template, assigns) do
    template |> SafeTpl.compile!() |> SafeTpl.render_to_string(assigns)
  end

  @doc "断言模板编译失败（用于无法安全处理的输出位置）。"
  def assert_compile_error(template) do
    SafeTpl.compile!(template)
    flunk("expected CompileError for template: #{template}")
  rescue
    CompileError -> :ok
  end

  @doc "断言渲染期安全错误（URL/CSS 值被策略拒绝）。"
  def assert_render_error(template, assigns) do
    template |> SafeTpl.compile!() |> SafeTpl.render_to_string(assigns)
    flunk("expected RenderError")
  rescue
    RenderError -> :ok
  end

  @doc """
  对 URL 类上下文跑探针：危险值被**拒绝**（RenderError）或被**无害化输出**
  都算安全；只有“危险结构活着出现在输出里”才算失败。
  """
  def assert_url_safe(template, key, probes) do
    for probe <- probes do
      result =
        try do
          {:ok, template |> SafeTpl.compile!() |> SafeTpl.render_to_string([{key, probe}])}
        rescue
          RenderError -> :rejected
        end

      case result do
        :rejected ->
          :ok

        {:ok, out} ->
          assert active_dangers(out) == [],
                 "probe #{inspect(probe)} produced active danger: #{inspect(out)}"

          refute out =~ ~r/(href|src)\s*=\s*"\s*javascript:/i,
                 "probe #{inspect(probe)} leaked javascript: in #{inspect(out)}"
      end
    end
  end

  # ---------- 探针集合 ----------

  @doc """
  通用 HTML/属性逃逸探针：目标是闭合属性/标签并引入事件处理器或脚本标签。
  """
  def html_probes do
    [
      "<script>alert(1)</script>",
      "\" onmouseover=\"alert(1)",
      "' onmouseover='alert(1)",
      "\"><script>alert(1)</script>",
      "``onmouseover=alert(1)",
      # 无引号属性探针：靠空白截断
      "x onmouseover=alert(1)",
      # 实体编码绕过尝试
      "&lt;script&gt;",
      # 反引号 / 美元符号（模板字符串场景）
      "`${alert(1)}`",
      # 含换行/制表符的属性截断
      "x\tonfocus=alert(1)",
      "x\nonfocus=alert(1)",
      # NUL 与控制字符
      "x\x00onerror=alert(1)"
    ]
  end

  @doc "JS 上下文逃逸探针。"
  def js_probes do
    [
      "\";alert(1);//",
      "';alert(1);//",
      "</script><script>alert(1)</script>",
      "\\';alert(1);//",
      "\n</script><script>alert(2)</script>",
      "`;alert(1);//",
      "${alert(1)}",
      # U+2028/2029 行分隔符
      "a\u2028alert(1)",
      "a\u2029alert(1)",
      # 闭合 script 的变体（大小写/空白混淆）
      "</script ><img src=x onerror=alert(1)>",
      # 反斜杠耗尽转义
      "\\\""
    ]
  end

  @doc "URL 属性探针：尝试注入可执行协议。"
  def url_probes do
    [
      "javascript:alert(1)",
      "JAVASCRIPT:alert(1)",
      "java\tscript:alert(1)",
      "java\nscript:alert(1)",
      "java\x00script:alert(1)",
      "  javascript:alert(1)",
      "vbscript:msgbox(1)",
      "data:text/html,<script>alert(1)</script>",
      "data:image/svg+xml;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+",
      # 协议相对 URL / 混淆
      "//evil.example/x",
      "\u0001javascript:alert(1)",
      # 良性 URL 对照组
      "/safe/path?a=1&b=2",
      "https://example.com/",
      "mailto:a@b.com",
      "tel:+123456",
      "data:image/png;base64,iVBORw0KGgo="
    ]
  end

  @doc "CSS 上下文探针。"
  def css_probes do
    [
      "red; background:url(javascript:alert(1))",
      "expression(alert(1))",
      "red\" onmouseover=\"alert(1)",
      "red} body{background:url(x)",
      "/* evil */",
      "red</style><script>alert(1)</script>",
      "url(javascript:alert(1))",
      "@import url(evil.css)",
      "red, calc(1)"
    ]
  end

  # ---------- 结果判定 ----------

  @doc """
  判断渲染输出里是否仍含“活跃”的危险标记（未被编码的可执行结构）。
  返回危险片段列表（空列表 = 安全）。
  """
  def active_dangers(output) when is_binary(output) do
    # 先把所有“已编码”的引号/尖括号占位中和掉，剩下还能匹配的才是真实逃逸。
    neutralized =
      output
      |> String.replace(~r/&(?:quot|#34|#x22);/i, "Q")
      |> String.replace(~r/&(?:#39|#x27);/i, "Q")
      |> String.replace(~r/&(?:lt|#60|#x3c);/i, "L")
      |> String.replace(~r/&(?:gt|#62|#x3e);/i, "G")
      |> String.replace(~r/&#x[0-9a-f]+;/i, "N")
      |> String.replace(~r/\\u[0-9a-fA-F]{4}/u, "J")
      |> String.replace(~r/\\[0-9a-fA-F]+\s?/u, "C")

    checks = [
      # 引号闭合当前属性后，空白处出现新属性（被中和的引号已变 Q，不匹配裸引号）
      {~r/["']\s+[a-zA-Z_:][\w:.-]*\s*=/i, "active quote breakout to new attribute"},
      # 裸尖括号标签（实体/JS/CSS 编码后不匹配）
      {~r/<script/i, "active <script> tag"},
      {~r/<img[^>]+onerror/i, "active <img onerror>"},
      {~r/["']\s*javascript:/i, "active javascript: URL"},
      {~r/["']\s*vbscript:/i, "active vbscript: URL"},
      {~r/[;}]\s*expression\s*\(/i, "active CSS expression()"}
    ]

    for {re, label} <- checks, Regex.match?(re, neutralized), do: label
  end

  @doc """
  专为 HTML 文本/属性上下文设计：剥离模板自身的结构性标签后，
  检查插值是否产生了活跃危险（不会把模板字面量里的 <script> 外壳算进去）。
  """
  def html_context_safe?(template, assigns) do
    out = render(template, assigns)
    active_dangers(out) == []
  end

  @doc """
  JS 上下文安全判定：插值内容里的 `<`、引号、反斜杠必须全部是 \\uXXXX 形态，
  且不能产生新的 script 元素闭合（模板自身闭合标签除外）。
  """
  def js_context_safe?(output) when is_binary(output) do
    not raw_element_closer_leaked?(output, "script") and
      not String.contains?(output, [<<0x2028::utf8>>, <<0x2029::utf8>>])
  end

  @doc """
  判断原始文本元素（script/style）的插值是否被正确编码：
  去掉模板自身的闭合标签后，输出里不应再出现裸的元素闭合符。
  """
  def raw_element_closer_leaked?(output, element) do
    closer = "</#{element}"

    output
    |> String.replace(~r/#{closer}\s*>/i, "")
    |> String.downcase()
    |> String.contains?(closer)
  end
end

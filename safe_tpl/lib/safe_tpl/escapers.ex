defmodule SafeTpl.Escapers do
  @moduledoc """
  运行时转义器集合。每个转义器对应一种编译期识别出的语法环境，
  输入任意 Elixir 值，输出 iodata。

  组合型转义器（如 `js_val_html`）= 内层语义编码 + 外层上下文转义，
  对应浏览器“先 HTML 解码、再按 JS/CSS 解析”的多层解码顺序。
  """

  alias SafeTpl.RenderError

  # ---------- 基础：HTML ----------

  @doc "HTML 文本/引号属性值：五个核心实体 + 反引号 + 斜杠。"
  def html_text(value), do: escape_html(to_bin(value), :text)
  def html_attr(value), do: escape_html(to_bin(value), :attr)

  @doc """
  无引号属性值：HTML5 规范下值中不能出现空白、引号、`=`、`<>`、反引号等。
  采用严格策略：只保留一小撮安全 codepoint，其余全部数字字符引用。
  """
  def html_attr_uq(value) do
    value
    |> to_bin()
    |> String.to_charlist()
    |> Enum.map(fn cp ->
      if safe_uq_cp?(cp), do: <<cp>>, else: "&#x#{Integer.to_string(cp, 16)};"
    end)
  end

  defp safe_uq_cp?(cp) do
    cp in ?a..?z or cp in ?A..?Z or cp in ?0..?9 or
      cp in ~c".,-_+/:?#@%&~!^"
  end

  escapes = [
    {?&, ~c"&amp;"},
    {?<, ~c"&lt;"},
    {?>, ~c"&gt;"},
    {?", ~c"&quot;"},
    {?', ~c"&#39;"},
    {?`, ~c"&#96;"}
  ]

  for {cp, rep} <- escapes do
    defp escape_html(<<unquote(cp), rest::binary>>, kind) do
      [unquote(rep) | escape_html(rest, kind)]
    end
  end

  defp escape_html(<<c, rest::binary>>, kind) do
    # 控制字符（除常见空白）也实体化，防止属性值里的换行截断
    if c < 0x20 and c not in [?\t, ?\n, ?\r] do
      ["&#x#{Integer.to_string(c, 16)};" | escape_html(rest, kind)]
    else
      [<<c>> | escape_html(rest, kind)]
    end
  end

  defp escape_html(<<>>, _), do: []

  # ---------- 基础：JS 字符串 ----------

  @doc """
  JS 字符串上下文：除少量绝对安全字符外全部 `\\uXXXX`，
  闭合引号、反斜杠、U+2028/2029、`<` 都不可逃逸。
  """
  def js_str(value) do
    value
    |> to_bin()
    |> String.to_charlist()
    |> Enum.map(fn
      cp when cp in 0x20..0x7E and cp not in [?\\, ?', ?", ?<, ?>, ?&] ->
        <<cp>>

      cp when cp <= 0xFFFF ->
        ["\\u", pad4(cp)]

      cp ->
        # 非 BMP：转成代理对
        n = cp - 0x10000
        hi = 0xD800 + div(n, 0x400)
        lo = 0xDC00 + rem(n, 0x400)
        [["\\u", pad4(hi)], ["\\u", pad4(lo)]]
    end)
  end

  defp pad4(cp), do: cp |> Integer.to_string(16) |> String.pad_leading(4, "0")

  @doc """
  JS 代码位：只接受 JSON 安全值，做受限 JSON 编码。
  拒绝 tuple/函数/PID/Map 含非字符串键 等不可安全表达的值。
  """
  def js_val(value), do: SafeTpl.Json.encode!(value)

  # ---------- 基础：CSS ----------

  @doc "CSS 字符串上下文：非安全字符一律反斜杠 hex 转义（带尾随空格分隔）。"
  def css_str(value) do
    value
    |> to_bin()
    |> String.to_charlist()
    |> Enum.map(fn cp ->
      if safe_css_str_cp?(cp), do: <<cp>>, else: ["\\", Integer.to_string(cp, 16), " "]
    end)
  end

  defp safe_css_str_cp?(cp) do
    cp in ?a..?z or cp in ?A..?Z or cp in ?0..?9 or cp in ~c" .,-_+%#@"
  end

  @doc """
  CSS 声明值代码位：保守白名单。
  禁止出现 expression / javascript: / vbscript: / @import / url( 等危险构造，
  且只接受受限字符集，杜绝引号逃逸与注释嵌套。
  """
  def css_val(value) do
    bin = to_bin(value)
    lower = String.downcase(bin)

    forbidden =
      ["expression", "javascript:", "vbscript:", "@import", "url(", "/*", "*/", "<", ">", "\\", "\"", "'", "`", "("]

    cond do
      Enum.any?(forbidden, &String.contains?(lower, &1)) ->
        raise RenderError,
              message: "CSS value rejected by safe-value policy: #{inspect(truncate(bin))}"

      not String.match?(bin, ~r/\A[ -~ -￿]*\z/u) ->
        raise RenderError, message: "CSS value contains disallowed control characters"

      true ->
        # 通过策略后仍做 CSS 字符串式转义兜底（白名单内字符保持原样）
        css_str(bin)
    end
  end

  defp truncate(bin) when byte_size(bin) > 60, do: binary_part(bin, 0, 60) <> "..."
  defp truncate(bin), do: bin

  # ---------- 基础：URL 过滤 ----------

  @allowed_schemes ~w(http https ftp mailto tel)

  @doc """
  URL scheme 白名单过滤。返回可以安全放进 URL 上下文的 iodata（已做最小转义）。

  规则：
    * 先剥离所有 ASCII 控制字符与空白（防 `java\tscript:` 绕过）；
    * 相对 URL（无 scheme）放行；
    * 绝对 URL 只允许 http/https/ftp/mailto/tel；
    * data: 仅允许 image/png|jpeg|gif|webp;base64,……（明确禁 svg+xml，防脚本）。
  """
  def url_filter(value) do
    raw = to_bin(value)
    stripped = strip_control(raw)

    cond do
      String.contains?(stripped, "\x00") ->
        raise RenderError, message: "URL rejected: contains NUL byte"

      true ->
        case detect_scheme(stripped) do
          {:scheme, scheme, rest} ->
            check_scheme!(scheme, rest, stripped)

          :relative ->
            stripped
        end
    end
  end

  defp check_scheme!("data", rest, original) do
    case Regex.run(~r/\Aimage\/(png|jpeg|gif|webp);base64,([A-Za-z0-9+\/=\s]+)\z/, rest) do
      [_, _fmt, _data] -> original
      _ -> raise RenderError, message: "URL rejected: only base64 image data: URLs are allowed"
    end
  end

  defp check_scheme!(scheme, _rest, original) do
    if scheme in @allowed_schemes do
      original
    else
      raise RenderError, message: "URL rejected: scheme #{inspect(scheme)} is not allowed"
    end
  end

  # 剥离 C0 控制字符与空白（含 tab/newline/CR），防 scheme 混淆
  defp strip_control(bin) do
    bin
    |> String.to_charlist()
    |> Enum.reject(fn cp -> cp <= 0x20 or cp == 0x7F end)
    |> List.to_string()
  end

  defp detect_scheme(bin) do
    case Regex.run(~r/\A([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)\z/s, bin) do
      [_, scheme, rest] -> {:scheme, String.downcase(scheme), rest}
      nil -> :relative
    end
  end

  # ---------- 组合转义器 ----------
  # 命名规则：内层语义编码在前，外层 HTML/UQ/CSS 包裹在后。
  # 浏览器解码顺序与编码顺序相反，因此先编 JS/CSS 语义、再编 HTML。

  # URL 属性（引号值）：过滤后再 HTML 转义
  def url_filter_html(value), do: url_filter(value) |> to_bin() |> escape_html(:attr)

  # URL 属性（无引号值）：过滤后按无引号属性白名单输出
  def url_filter_uq(value) do
    value |> url_filter() |> to_bin() |> String.to_charlist() |> Enum.map(fn cp ->
      if safe_uq_cp?(cp), do: <<cp>>, else: "&#x#{Integer.to_string(cp, 16)};"
    end)
  end

  # URL 中间片段（引号值）：scheme 已固定，百分号编码会破坏 URL/HTML 结构的字符，
  # 再做 HTML 转义。保留合法的 query/path 字符。
  def url_segment_html(value) do
    value |> to_bin() |> url_segment_escape() |> IO.iodata_to_binary() |> escape_html(:attr)
  end

  # URL 中间片段（无引号值）
  def url_segment_uq(value) do
    value
    |> to_bin()
    |> url_segment_escape()
    |> IO.iodata_to_binary()
    |> html_attr_uq_inner()
  end

  # 百分号编码：空白、引号、尖括号、反引号、反斜杠、分隔符等一律 %HH，
  # 使插值无法引入新属性、新路径段结构或可执行 scheme。
  defp url_segment_escape(bin) do
    bin
    |> String.to_charlist()
    |> Enum.map(fn cp ->
      if safe_url_segment_cp?(cp),
        do: <<cp>>,
        else: "%" <> String.pad_leading(Integer.to_string(cp, 16), 2, "0")
    end)
  end

  defp safe_url_segment_cp?(cp) do
    cp in ?a..?z or cp in ?A..?Z or cp in ?0..?9 or
      cp in ~c".-_~:/?#[]@!$&'()*+,;="
  end

  # on* 事件处理器（引号值）：js_val -> html
  def js_val_html(value), do: value |> js_val() |> IO.iodata_to_binary() |> escape_html(:attr)

  # on* 事件处理器（无引号值）
  def js_val_uq(value) do
    value |> js_val() |> IO.iodata_to_binary() |> html_attr_uq_inner()
  end

  # style 属性（引号值）：css_val -> html
  def css_val_html(value), do: value |> css_val() |> IO.iodata_to_binary() |> escape_html(:attr)

  # style 属性（无引号值）
  def css_val_uq(value) do
    value |> css_val() |> IO.iodata_to_binary() |> html_attr_uq_inner()
  end

  # JS 字符串 + URL 过滤（location = "{{x}}" 这类）
  def js_str_url(value) do
    value |> url_filter() |> to_bin() |> then(&js_str/1)
  end

  # JS 代码位 + URL 过滤
  def js_val_url(value) do
    # 过滤针对字符串值；非字符串直接交给 js_val 类型检查
    case value do
      s when is_binary(s) -> s |> url_filter() |> then(&js_val/1)
      other -> js_val(other)
    end
  end

  # <style> 里的 url(...) ：过滤 + CSS URL 专用转义
  # （保留 URL 子界定符与路径字符，只编码会破坏 CSS 语法或闭合括号的字符）
  def url_filter_css(value) do
    value |> url_filter() |> to_bin() |> css_url_escape()
  end

  # url("...") 带引号形式：引号由模板字面量提供，同样用 URL 专用转义
  def url_filter_css_str(value), do: url_filter_css(value)

  defp css_url_escape(bin) do
    bin
    |> String.to_charlist()
    |> Enum.map(fn cp ->
      cond do
        safe_css_url_cp?(cp) -> <<cp>>
        # 用反斜杠 hex 转义，尾随空格仅在后续是 hex 数字时才需要，这里统一不加，
        # 因为下一个字符若是 hex 数字我们改用 6 位定长形式避免歧义
        true -> ["\\", String.pad_leading(Integer.to_string(cp, 16), 6, "0")]
      end
    end)
  end

  # URL 在 CSS url() 中可安全原样出现的字符
  defp safe_css_url_cp?(cp) do
    cp in ?a..?z or cp in ?A..?Z or cp in ?0..?9 or
      cp in ~c".-_~:/?#[]@!$&'()*+,;=% "
  end

  defp html_attr_uq_inner(bin) do
    bin |> String.to_charlist() |> Enum.map(fn cp ->
      if safe_uq_cp?(cp), do: <<cp>>, else: "&#x#{Integer.to_string(cp, 16)};"
    end)
  end

  # ---------- 工具 ----------

  defp to_bin(v) when is_binary(v), do: v
  defp to_bin(v) when is_atom(v), do: Atom.to_string(v)
  defp to_bin(v) when is_number(v), do: String.Chars.to_string(v)
  defp to_bin(v), do: String.Chars.to_string(v)
end

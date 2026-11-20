defmodule SafeTpl.JsScanner do
  @moduledoc ~S"""
  `<script>` 内容的 JS 词法状态机（编译期）。

  两层判断：

  1. **词法模式**由逐字符状态机跟踪：`code / sq / dq / tpl / line_comment /
     block_comment / regex`，决定插值点的基础转义器。
  2. **URL 接收位**无法逐字符可靠判断，改为在每个插值点取“当前 script 块内
     截至该点的源码前缀”做词法预扫描（`mark_sinks/1`），命中则把字符串类
     转义升级为“先 URL scheme 白名单过滤”。

  | 模式 | 插值处理 |
  |---|---|
  | `code` | `js_val`（只允许 JSON 安全值：binary/number/boolean/nil/原子/数组/映射） |
  | `sq` / `dq` | `js_str`（不可信字符一律 `\uXXXX`，引号与反斜杠无法逃逸） |
  | `tpl`（反引号） | **编译报错**（`${...}` 使插值成为可执行代码） |
  | 注释 / 正则 | **编译报错** |

  字符串转义把 `<` 也转成 `\u003c`，因此插值内容不可能提前闭合 `<script>`。
  """

  alias SafeTpl.{CompileError, Context}

  @doc "进入 script 元素时初始化。"
  def init(%Context{} = ctx) do
    %{ctx | js_mode: :code, js_escape: false, js_prev: nil, raw_buf: ""}
  end

  @doc "插值点决策。prefix 为当前 script 块截至插值点的完整源码。"
  def escaper_for(%Context{} = ctx, prefix, meta) do
    url? = mark_sinks(prefix)

    case ctx.js_mode do
      :code -> if url?, do: :js_val_url, else: :js_val
      :sq -> if url?, do: :js_str_url, else: :js_str
      :dq -> if url?, do: :js_str_url, else: :js_str
      :tpl ->
        raise CompileError,
              message: "interpolation inside a JS template literal is not allowed (${...} makes it executable code)",
              line: meta[:line], col: meta[:col]
      :line_comment ->
        raise CompileError, message: "interpolation inside a JS line comment is not allowed",
              line: meta[:line], col: meta[:col]
      :block_comment ->
        raise CompileError, message: "interpolation inside a JS block comment is not allowed",
              line: meta[:line], col: meta[:col]
      :regex ->
        raise CompileError, message: "interpolation inside a JS regex literal is not allowed",
              line: meta[:line], col: meta[:col]
      :slash_pending ->
        raise CompileError,
              message: "interpolation at a slash position is not allowed (regex/division context cannot be safely escaped)",
              line: meta[:line], col: meta[:col]
    end
  end

  @doc "消费 script 原始文本；识别到闭合标签时退回 HTML 主状态机。"
  def feed_text(%Context{} = ctx, text) do
    case :binary.match(text, ["</script", "</SCRIPT", "</Script"]) do
      {offset, _len} ->
        lit = binary_part(text, 0, offset)
        close_part = binary_part(text, offset, byte_size(text) - offset)
        ctx2 = feed_literal(%{ctx | raw_buf: ctx.raw_buf <> lit}, lit)
        html_ctx = %{ctx2 | state: :text, js_mode: :code, raw_buf: ""}
        Context.feed_text(html_ctx, close_part, %{})

      :nomatch ->
        feed_literal(%{ctx | raw_buf: ctx.raw_buf <> text}, text)
    end
  end

  # ---------- 逐字符状态机 ----------

  defp feed_literal(ctx, <<>>), do: ctx

  defp feed_literal(%Context{js_mode: :code} = ctx, <<c, rest::binary>>) do
    case c do
      ?/ when ctx.js_prev == ?/ ->
        feed_literal(%{ctx | js_mode: :line_comment, js_prev: c}, rest)
      ?* when ctx.js_prev == ?/ ->
        feed_literal(%{ctx | js_mode: :block_comment, js_prev: c}, rest)
      ?' ->
        feed_literal(%{ctx | js_mode: :sq, js_escape: false, js_prev: c}, rest)
      ?" ->
        feed_literal(%{ctx | js_mode: :dq, js_escape: false, js_prev: c}, rest)
      ?` ->
        feed_literal(%{ctx | js_mode: :tpl, js_escape: false, js_prev: c}, rest)
      ?/ ->
        # 斜杠语义待定：下一个字符决定是 // 注释、/* 注释还是正则/除号
        feed_literal(%{ctx | js_mode: :slash_pending, js_prev: c}, rest)
      _ ->
        feed_literal(%{ctx | js_prev: c}, rest)
    end
  end

  # 斜杠待定：/ 后面的字符决定最终模式
  defp feed_literal(%Context{js_mode: :slash_pending} = ctx, <<c, rest::binary>>) do
    case c do
      ?/ -> feed_literal(%{ctx | js_mode: :line_comment, js_prev: c}, rest)
      ?* -> feed_literal(%{ctx | js_mode: :block_comment, js_prev: c}, rest)
      _ ->
        if regex_allowed?(ctx.js_prev) do
          # 第一个 / 是正则起始符，当前字符按正则内容处理
          feed_literal(%{ctx | js_mode: :regex, js_escape: false, js_prev: c}, rest)
        else
          # 除号：回到 code 重新处理当前字符
          feed_literal(%{ctx | js_mode: :code, js_prev: ?/}, <<c, rest::binary>>)
        end
    end
  end

  defp feed_literal(%Context{js_mode: :line_comment} = ctx, <<c, rest::binary>>) do
    if c == ?\n,
      do: feed_literal(%{ctx | js_mode: :code, js_prev: c}, rest),
      else: feed_literal(ctx, rest)
  end

  defp feed_literal(%Context{js_mode: :block_comment} = ctx, <<c, rest::binary>>) do
    if ctx.js_prev == ?* and c == ?/,
      do: feed_literal(%{ctx | js_mode: :code, js_prev: c}, rest),
      else: feed_literal(%{ctx | js_prev: c}, rest)
  end

  defp feed_literal(%Context{js_mode: m} = ctx, <<c, rest::binary>>)
       when m in [:sq, :dq] do
    closing = if m == :sq, do: ?', else: ?"

    cond do
      ctx.js_escape -> feed_literal(%{ctx | js_escape: false, js_prev: c}, rest)
      c == ?\\ -> feed_literal(%{ctx | js_escape: true, js_prev: c}, rest)
      c == closing -> feed_literal(%{ctx | js_mode: :code, js_escape: false, js_prev: c}, rest)
      true -> feed_literal(%{ctx | js_prev: c}, rest)
    end
  end

  defp feed_literal(%Context{js_mode: :tpl} = ctx, <<c, rest::binary>>) do
    cond do
      ctx.js_escape -> feed_literal(%{ctx | js_escape: false, js_prev: c}, rest)
      c == ?\\ -> feed_literal(%{ctx | js_escape: true, js_prev: c}, rest)
      c == ?` -> feed_literal(%{ctx | js_mode: :code, js_escape: false, js_prev: c}, rest)
      true -> feed_literal(%{ctx | js_prev: c}, rest)
    end
  end

  defp feed_literal(%Context{js_mode: :regex} = ctx, <<c, rest::binary>>) do
    cond do
      ctx.js_escape -> feed_literal(%{ctx | js_escape: false, js_prev: c}, rest)
      c == ?\\ -> feed_literal(%{ctx | js_escape: true, js_prev: c}, rest)
      c == ?/ -> feed_literal(%{ctx | js_mode: :code, js_escape: false, js_prev: c}, rest)
      true -> feed_literal(%{ctx | js_prev: c}, rest)
    end
  end

  # 上一个有效字符决定 `/` 起始的是正则还是除号
  defp regex_allowed?(prev) do
    case prev do
      nil -> true
      p when p in [?(, ?,, ?=, ?:, ?;, ?[, ?{, ?&, ?|, ??, ?+, ?-, ?*, ?%, ?<, ?>, ?!] -> true
      _ -> false
    end
  end

  @doc """
  URL 接收位启发式（对插值点前缀做词法匹配）：

      location = ... / location.href = ...
      fetch( ... / xhr.open( ... / window.open( ...
      标识符以 url|src|href|uri 结尾的赋值目标

  命中后字符串插值会先经 URL scheme 白名单过滤，防止 `javascript:` 等协议注入。
  """
  def mark_sinks(prefix) when is_binary(prefix) do
    # 去掉前缀里完整的字符串/注释，降低误报成本
    cleaned = strip_noise(prefix)
    # 字符串模式下，当前字符串的开引号已被消费但不在“完整字符串”里，
    # 因此前缀末尾可能残留一个引号；各模式统一允许结尾可选引号/空白。
    q = ~s/["']?/

    patterns = [
      Regex.compile!("\\blocation(\\.[A-Za-z_$][\\w$]*)*\\s*=[^=]\\s*#{q}$", "s"),
      Regex.compile!("\\bfetch\\s*\\(\\s*#{q}$", "s"),
      Regex.compile!("\\.(?:open|assign|replace)\\s*\\([^,)]*#{q}$", "s"),
      Regex.compile!("[A-Za-z_$][\\w$]*(?:url|src|href|[Uu][Rr][Ii])\\s*=\\s*#{q}$", "s")
    ]

    Enum.any?(patterns, &Regex.match?(&1, cleaned))
  end

  defp strip_noise(bin) do
    bin
    |> String.replace(~r/'(?:\\.|[^'\\])*'/, "''")
    |> String.replace(~r/"(?:\\.|[^"\\])*"/, ~s(""))
    |> String.replace(~r/`(?:\\.|[^`\\])*`/, "``")
    |> String.replace(~r|//[^\n]*|, "")
    |> String.replace(~r|/\*.*?\*/|, "")
  end
end

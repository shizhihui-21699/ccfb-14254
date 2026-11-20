defmodule SafeTpl.Context do
  @moduledoc ~S"""
  编译期 HTML 语法环境状态机。

  状态机在模板 AST 的文本片段上逐字符推进，遇到插值点时根据**当前状态**决定
  该点的转义器，并把决定写回 AST 节点的 `meta.escaper`。

  ## 状态集合

  | 状态 | 含义 | 插值处理 |
  |---|---|---|
  | `text` | HTML 元素文本 | `html_text` |
  | `tag` | 标签内部（标签名/属性名/属性值） | 见下，名字位置一律报错 |
  | `script` | `<script>` 原始文本 | 交给 `SafeTpl.JsScanner` |
  | `style` | `<style>` 原始文本 | 交给 `SafeTpl.CssScanner` |
  | `comment` | `<!-- ... -->` | **编译报错** |
  | `doctype` | `<!...>` | **编译报错** |

  `tag` 状态内部再用 `sub` 区分：
  `name / attr_name / before_value / value_q / value_uq`，
  并记录当前属性名（用于识别 URL 属性、style 属性、事件处理器）。

  ## 分支合并

  `{% if %}` 的两个分支、`{% for %}` 的循环体都可能改变环境。
  安全要求：控制块结束后环境必须与进入时**完全一致**，否则同一个后续插值点
  在不同运行路径下处于不同环境，单一转义器无法同时保证安全——直接编译报错。
  """

  defstruct state: :text,
            sub: nil,
            quote: nil,
            attr: nil,
            tag: nil,
            stack: [],
            value_start?: false,
            # JS 子扫描器（state == :script 时有效）
            js_mode: :code,
            js_escape: false,
            js_prev: nil,
            js_url_pending: false,
            # CSS 子扫描器（state == :style 或 style 属性时有效）
            css_mode: :code,
            css_escape: false,
            css_url_pending: false,
            # 原始文本元素的累积缓冲（JS/CSS 前缀判断用）
            raw_buf: "",
            # 上一个文本字符是孤立的 "<" 或 "</"：下一个插值点若出现即标签名位置
            pending_lt: false

  alias SafeTpl.CompileError

  @void_tags ~w(area base br col embed hr img input link meta param source track wbr)
  @raw_tags ~w(script style textarea title)

  @url_attrs ~w(href src action formaction poster cite data icon manifest archive background
                longdesc profile usemap codebase)
  @style_attr "style"

  # ---------- 入口 ----------

  @doc "在给定初始状态下消费一段模板文本，返回推进后的状态。"
  def feed_text(%__MODULE__{} = ctx, text, meta) when is_binary(text) do
    scan(text, ctx, meta)
  end

  @doc "插值点：按当前状态选择转义器，返回 escaper 名称（atom）。"
  def escaper_for_interp(%__MODULE__{state: :text, pending_lt: true}, meta) do
    raise CompileError,
          message: "interpolation in an unsafe position (tag name position); interpolating a whole tag name cannot be safely escaped",
          line: meta[:line],
          col: meta[:col]
  end

  def escaper_for_interp(%__MODULE__{state: :text}, _meta), do: :html_text

  def escaper_for_interp(%__MODULE__{state: :comment}, meta) do
    raise CompileError,
          message: "interpolation inside an HTML comment is not allowed (comments can be folded into the DOM by flawed parsers)",
          line: meta[:line],
          col: meta[:col]
  end

  def escaper_for_interp(%__MODULE__{state: :doctype}, meta) do
    raise CompileError,
          message: "interpolation inside a DOCTYPE declaration is not allowed",
          line: meta[:line],
          col: meta[:col]
  end

  def escaper_for_interp(%__MODULE__{state: :script} = ctx, meta) do
    SafeTpl.JsScanner.escaper_for(ctx, ctx.raw_buf, meta)
  end

  def escaper_for_interp(%__MODULE__{state: :style} = ctx, meta) do
    SafeTpl.CssScanner.escaper_for(ctx, ctx.raw_buf, meta)
  end

  def escaper_for_interp(%__MODULE__{state: :tag, sub: sub} = ctx, meta)
      when sub in [:name, :attr_name, :before_value] do
    # 形如 attr={{ x }}：等号已消费、值尚未开始，插值本身就是（无引号）值
    if sub == :before_value and ctx.value_start? do
      escaper_for_interp(%{ctx | sub: :value_uq}, meta)
    else
      reason =
        case sub do
          :name -> "tag name position"
          :attr_name -> "attribute name position"
          :before_value -> "position between attributes (unquoted value missing)"
        end

      raise CompileError,
            message:
              "interpolation in an unsafe position (#{reason}); only complete attribute values can be safely escaped",
            line: meta[:line],
            col: meta[:col]
    end
  end

  # 引号包裹的属性值
  def escaper_for_interp(%__MODULE__{state: :tag, sub: :value_q} = ctx, _meta) do
    cond do
      # 值首：插值决定整个 URL，做 scheme 白名单过滤
      url_attr?(ctx.attr) and ctx.value_start? ->
        :url_filter_html

      # URL 中间片段：scheme 已由前面的字面量固定，百分号编码危险字符即可
      url_attr?(ctx.attr) ->
        :url_segment_html

      js_handler?(ctx.attr) ->
        # on*="..."：属性值是一段 JS 代码。浏览器先 HTML 解码再当 JS 执行，
        # 因此编码必须保证 JS 语义安全后再 HTML 转义。
        :js_val_html

      ctx.attr == @style_attr ->
        # style="..."：浏览器先 HTML 解码再当 CSS 解析
        :css_val_html

      true ->
        :html_attr
    end
  end

  # 无引号属性值
  def escaper_for_interp(%__MODULE__{state: :tag, sub: :value_uq} = ctx, _meta) do
    cond do
      url_attr?(ctx.attr) and ctx.value_start? ->
        :url_filter_uq

      url_attr?(ctx.attr) ->
        :url_segment_uq

      js_handler?(ctx.attr) ->
        :js_val_uq

      ctx.attr == @style_attr ->
        :css_val_uq

      true ->
        :html_attr_uq
    end
  end

  @doc """
  控制结构合并：两个分支结束后的环境必须结构一致。
  不一致即编译报错（同一插值点可能在不同运行路径落到不同环境）。
  """
  def merge_contexts!(%__MODULE__{} = a, %__MODULE__{} = b, meta) do
    cond do
      a.stack != b.stack ->
        raise CompileError,
              message:
                "branches leave the HTML element stack unbalanced " <>
                  "(#{inspect(a.stack)} vs #{inspect(b.stack)}); unclosed tags across branches make later context ambiguous",
              line: meta[:line],
              col: meta[:col]

      comparable(a) != comparable(b) ->
        raise CompileError,
              message:
                "branches end in different syntactic contexts " <>
                  "(#{describe(a)} vs #{describe(b)}); a single interpolation after the branch cannot be safely escaped for both",
              line: meta[:line],
              col: meta[:col]

      true ->
        a
    end
  end

  defp comparable(%__MODULE__{state: :tag} = c) do
    # 标签内部：当前属性名直接决定 URL/JS/CSS 语义，必须严格一致
    {:tag, c.sub, c.quote, c.attr, c.value_start?}
  end

  defp comparable(%__MODULE__{} = c) do
    {c.state, c.sub, c.quote, c.value_start?,
     c.js_mode, c.js_url_pending, c.css_mode, c.css_url_pending}
  end

  defp describe(%__MODULE__{state: :tag, sub: sub, attr: attr}), do: "tag(#{sub}, attr=#{inspect(attr)})"
  defp describe(%__MODULE__{state: s}), do: to_string(s)

  # ---------- HTML 文本扫描 ----------

  defp scan(<<>>, ctx, _meta), do: ctx

  # 标签内部 / 原始文本元素：逐字符专用派发，避免被前缀匹配子句截胡
  defp scan(text, %__MODULE__{state: :tag} = ctx, meta), do: scan_tag(text, ctx, meta)

  defp scan(text, %__MODULE__{state: :script} = ctx, _meta) do
    SafeTpl.JsScanner.feed_text(ctx, text)
  end

  defp scan(text, %__MODULE__{state: :style} = ctx, _meta) do
    SafeTpl.CssScanner.feed_text(ctx, text)
  end

  # 注释 / 声明开头
  defp scan("<!--" <> rest, ctx, meta), do: scan_decl(rest, %{ctx | state: :comment}, :comment, meta)
  defp scan("<!" <> rest, ctx, meta), do: scan_decl(rest, %{ctx | state: :doctype}, :doctype, meta)
  defp scan("<?" <> _rest, _ctx, meta) do
    raise CompileError, message: "processing instruction <?...?> is not allowed in templates", line: meta[:line], col: meta[:col]
  end

  # 闭合标签
  defp scan("</" <> rest, ctx, meta) do
    case tag_name(rest) do
      {name, after_name} ->
        rest2 = skip_to_gt(after_name)
        ctx2 = close_tag(ctx, name, meta)
        scan(rest2, ctx2, meta)

      :no_name ->
        # 不是合法闭合标签：把 "<" 当普通文本，"/" 与剩余部分重新扫描
        scan(<<"/", rest::binary>>, ctx, meta)
    end
  end

  # 开始标签
  defp scan("<" <> rest, ctx, meta) do
    case tag_name(rest) do
      {name, after_name} ->
        ctx2 = %{ctx | state: :tag, sub: :name, tag: name, attr: nil, quote: nil, value_start?: false, pending_lt: false}
        scan(after_name, ctx2, meta)

      :no_name ->
        # 不是合法标签开始（典型：< 后紧跟模板插值）。标记孤立 "<"，
        # 若下一个 AST 节点是插值，escaper_for_interp 会按标签名位置拒绝。
        scan(rest, %{ctx | pending_lt: true}, meta)
    end
  end

  defp scan(<<_c, rest::binary>>, ctx, meta), do: scan(rest, %{ctx | pending_lt: false}, meta)

  # 标签内部逐字符；一旦 finish_open_tag 切出 :tag（进入 text/script/style），
  # 剩余文本必须交回主 scan 重新派发
  defp scan_tag(<<>>, ctx, _meta), do: ctx

  defp scan_tag(bin, %__MODULE__{state: state} = ctx, meta) when state != :tag do
    scan(bin, ctx, meta)
  end

  defp scan_tag(<<c, rest::binary>>, ctx, meta) do
    scan_tag(rest, tag_char(ctx, c), meta)
  end

  # 注释/DOCTYPE 内部：只找结束符，插值会在 Analyzer 层按 :comment/:doctype 状态拒绝
  defp scan_decl(bin, ctx, kind, meta) do
    terminator = if kind == :comment, do: "-->", else: ">"

    case :binary.match(bin, terminator) do
      {offset, len} ->
        after_t = binary_part(bin, offset + len, byte_size(bin) - offset - len)
        scan(after_t, %{ctx | state: :text}, meta)

      :nomatch ->
        raise CompileError,
              message: "unterminated #{kind} declaration",
              line: meta[:line],
              col: meta[:col]
    end
  end

  # ---------- 标签内部字符推进 ----------
  # tag_char/2 的各 sub 子句定义在下方

  defp tag_char(%__MODULE__{sub: :attr_name} = ctx, c) do
    case c do
      ?\s -> ctx
      ?\t -> ctx
      ?\n -> ctx
      ?\f -> ctx
      ?/ -> %{ctx | sub: :before_value}
      ?> -> finish_open_tag(ctx)
      ?= ->
        %{ctx | sub: :before_value, value_start?: true}
      c when c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?-, ?_, ?:, ?.] ->
        %{ctx | attr: append_attr(ctx.attr, c)}
      _ ->
        # 杂散字符（含引号）：停留在 attr_name，浏览器容错下属性名解析复杂，
        # 保守地视为新属性名起点
        %{ctx | attr: append_attr(ctx.attr, c)}
    end
  end

  defp tag_char(%__MODULE__{sub: :before_value} = ctx, c) do
    case c do
      ?\s -> ctx
      ?\t -> ctx
      ?\n -> ctx
      ?\f -> ctx
      ?/ -> ctx
      ?> -> finish_open_tag(ctx)
      ?" -> %{ctx | sub: :value_q, quote: ?", value_start?: ctx.value_start?}
      ?' -> %{ctx | sub: :value_q, quote: ?', value_start?: ctx.value_start?}
      _ ->
        %{ctx | sub: :value_uq, quote: nil, value_start?: ctx.value_start?}
        |> tag_value_char(c)
    end
  end

  defp tag_char(%__MODULE__{sub: :value_q, quote: q} = ctx, c) do
    if c == q do
      %{ctx | sub: :attr_name, quote: nil, attr: nil, value_start?: false}
    else
      # 值内容：一旦出现非空白字面量，后续插值就不是“值首”，不能再做 scheme 过滤
      if ctx.value_start? and not ws?(c), do: %{ctx | value_start?: false}, else: ctx
    end
  end

  defp tag_char(%__MODULE__{sub: :value_uq} = ctx, c) do
    case c do
      ?\s -> %{ctx | sub: :attr_name, attr: nil, value_start?: false}
      ?\t -> %{ctx | sub: :attr_name, attr: nil, value_start?: false}
      ?\n -> %{ctx | sub: :attr_name, attr: nil, value_start?: false}
      ?\f -> %{ctx | sub: :attr_name, attr: nil, value_start?: false}
      ?> -> finish_open_tag(ctx)
      _ -> tag_value_char(ctx, c)
    end
  end

  defp tag_char(%__MODULE__{sub: :name} = ctx, c) do
    case c do
      ?\s -> %{ctx | sub: :attr_name}
      ?\t -> %{ctx | sub: :attr_name}
      ?\n -> %{ctx | sub: :attr_name}
      ?\f -> %{ctx | sub: :attr_name}
      ?> -> finish_open_tag(ctx)
      _ -> %{ctx | tag: ctx.tag <> <<c>>}
    end
  end

  defp tag_value_char(ctx, c) do
    if ctx.value_start? and not ws?(c), do: %{ctx | value_start?: :filled}, else: ctx
  end

  defp ws?(c), do: c in [?\s, ?\t, ?\n, ?\f, ?\r]

  defp append_attr(nil, c), do: <<c>>
  defp append_attr(name, c), do: name <> <<c>>

  # ---------- 标签开关与栈 ----------

  defp finish_open_tag(ctx) do
    name = String.downcase(ctx.tag)

    cond do
      name in @void_tags ->
        %{ctx | state: :text, tag: nil, attr: nil, sub: nil, value_start?: false}

      name == "script" ->
        SafeTpl.JsScanner.init(%{
          ctx
          | state: :script,
            sub: nil,
            attr: nil,
            value_start?: false,
            stack: [name | ctx.stack]
        })

      name == "style" ->
        SafeTpl.CssScanner.init(%{
          ctx
          | state: :style,
            sub: nil,
            attr: nil,
            value_start?: false,
            stack: [name | ctx.stack]
        })

      name in @raw_tags ->
        # textarea/title：原始文本元素，内部没有标签解析，插值按文本转义即可
        %{ctx | state: :text, sub: nil, attr: nil, value_start?: false, stack: [name | ctx.stack]}

      true ->
        %{ctx | state: :text, sub: nil, attr: nil, value_start?: false, stack: [name | ctx.stack]}
    end
  end

  defp close_tag(ctx, raw_name, meta) do
    name = String.downcase(raw_name)

    case ctx.stack do
      [^name | rest] ->
        %{ctx | state: :text, stack: rest, tag: nil, attr: nil, sub: nil}

      [top | _] ->
        raise CompileError,
              message: "closing tag </#{name}> does not match the open tag <#{top}> (unbalanced tags make context analysis unreliable)",
              line: meta[:line],
              col: meta[:col]

      [] ->
        raise CompileError,
              message: "closing tag </#{name}> has no matching open tag",
              line: meta[:line],
              col: meta[:col]
    end
  end

  # ---------- 小工具 ----------

  defp tag_name(<<c, _::binary>> = bin) when c in ?a..?z or c in ?A..?Z do
    {name, rest} = take_while(bin, fn ch -> ch in ?a..?z or ch in ?A..?Z or ch in ?0..?9 or ch in [?-, ?_] end)
    {String.downcase(name), rest}
  end

  defp tag_name(_), do: :no_name

  defp take_while(bin, fun), do: take_while(bin, fun, [])

  defp take_while(<<c, rest::binary>>, fun, acc) do
    if fun.(c) do
      take_while(rest, fun, [c | acc])
    else
      # 终止：acc 是逆序的已消费字符，bin 是尚未消费的完整剩余串
      name = acc |> Enum.reverse() |> List.to_string()
      {name, <<c, rest::binary>>}
    end
  end

  defp take_while(<<>>, _fun, acc), do: {acc |> Enum.reverse() |> List.to_string(), <<>>}

  defp skip_to_gt(bin) do
    case :binary.match(bin, ">") do
      {offset, 1} -> binary_part(bin, offset + 1, byte_size(bin) - offset - 1)
      :nomatch -> <<>>
    end
  end

  defp url_attr?(name) when is_binary(name) do
    n = String.downcase(name)
    n in @url_attrs or String.ends_with?(n, "srcset")
  end
  defp url_attr?(_), do: false

  defp js_handler?(<<?o, ?n, _::binary>>), do: true
  defp js_handler?(_), do: false
end

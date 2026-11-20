defmodule SafeTpl.CssScanner do
  @moduledoc ~S"""
  `<style>` 元素与 `style=""` 属性的 CSS 词法状态机（编译期）。

  | 模式 | 含义 | 插值处理 |
  |---|---|---|
  | `code` | 声明/规则代码位 | `css_val`（安全值白名单，禁 `expression`/`javascript:` 等） |
  | `sq` / `dq` | CSS 字符串内 | `css_str`（非安全字符一律 `\\HHHHHH` hex 转义） |
  | `block_comment` | `/* ... */` 内 | **编译报错**（旧 IE 可在注释里解析 expression） |
  | `url_bare` | `url(...)` 的裸 URL 位 | `url_filter_css`（scheme 白名单 + CSS 转义） |

  设计要点：

  * `url("...")` 带引号时走字符串模式，转义器在字符串上下文内再做 URL 过滤
    （由 Analyzer 根据 `css_url_pending` 标记决定）。
  * 闭合 `</style>` 退回 HTML 主状态机。
  """

  alias SafeTpl.{CompileError, Context}

  def init(%Context{} = ctx) do
    %{ctx | css_mode: :code, css_escape: false, css_url_pending: false, raw_buf: ""}
  end

  def escaper_for(%Context{css_mode: mode, css_url_pending: url?}, _prefix, meta) do
    case {mode, url?} do
      {:code, true} -> :url_filter_css
      {:code, false} -> :css_val
      {:sq, true} -> :url_filter_css_str
      {:dq, true} -> :url_filter_css_str
      {:sq, false} -> :css_str
      {:dq, false} -> :css_str
      {:block_comment, _} ->
        raise CompileError,
              message: "interpolation inside a CSS comment is not allowed",
              line: meta[:line], col: meta[:col]
      {:url_bare, _} -> :url_filter_css
    end
  end

  def feed_text(%Context{} = ctx, text) do
    case :binary.match(text, ["</style", "</STYLE", "</Style"]) do
      {offset, _len} ->
        lit = binary_part(text, 0, offset)
        close_part = binary_part(text, offset, byte_size(text) - offset)
        ctx2 = feed_literal(%{ctx | raw_buf: ctx.raw_buf <> lit}, lit)
        html_ctx = %{ctx2 | state: :text, css_mode: :code, css_url_pending: false, raw_buf: ""}
        Context.feed_text(html_ctx, close_part, %{})

      :nomatch ->
        feed_literal(%{ctx | raw_buf: ctx.raw_buf <> text}, text)
    end
  end

  # ---------- 逐字符状态机 ----------

  defp feed_literal(ctx, <<>>), do: ctx

  # code 模式
  defp feed_literal(%Context{css_mode: :code} = ctx, <<c, rest::binary>>) do
    case c do
      ?' -> feed_literal(%{ctx | css_mode: :sq, css_escape: false}, rest)
      ?" -> feed_literal(%{ctx | css_mode: :dq, css_escape: false}, rest)
      ?/ -> feed_literal(%{ctx | css_mode: :code_slash}, rest)
      ?) -> feed_literal(%{ctx | css_url_pending: false}, rest)
      _ -> maybe_enter_url(%{ctx | css_escape: false}, c, rest)
    end
  end

  # code 中遇到 /，下一个 * 才进入注释
  defp feed_literal(%Context{css_mode: :code_slash} = ctx, <<c, rest::binary>>) do
    case c do
      ?* -> feed_literal(%{ctx | css_mode: :block_comment, css_escape: false}, rest)
      ?/ -> feed_literal(%{ctx | css_mode: :code_slash}, rest)
      _ -> feed_literal(%{ctx | css_mode: :code}, <<c, rest::binary>>)
    end
  end

  # 块注释
  defp feed_literal(%Context{css_mode: :block_comment} = ctx, <<c, rest::binary>>) do
    case {ctx.css_escape, c} do
      {:star, ?/} -> feed_literal(%{ctx | css_mode: :code, css_escape: false}, rest)
      {_, ?*} -> feed_literal(%{ctx | css_escape: :star}, rest)
      _ -> feed_literal(%{ctx | css_escape: false}, rest)
    end
  end

  # 字符串
  defp feed_literal(%Context{css_mode: m} = ctx, <<c, rest::binary>>)
       when m in [:sq, :dq] do
    closing = if m == :sq, do: ?', else: ?"

    cond do
      ctx.css_escape -> feed_literal(%{ctx | css_escape: false}, rest)
      c == ?\\ -> feed_literal(%{ctx | css_escape: true}, rest)
      c == closing -> feed_literal(%{ctx | css_mode: :code, css_escape: false}, rest)
      true -> feed_literal(ctx, rest)
    end
  end

  # url( 之后的裸 URL 位
  defp feed_literal(%Context{css_mode: :url_bare} = ctx, <<c, rest::binary>>) do
    case c do
      ?) -> feed_literal(%{ctx | css_mode: :code, css_url_pending: false}, rest)
      ?' -> feed_literal(%{ctx | css_mode: :sq, css_url_pending: true}, rest)
      ?" -> feed_literal(%{ctx | css_mode: :dq, css_url_pending: true}, rest)
      _ -> feed_literal(ctx, rest)
    end
  end

  # 识别 "url(" 序列：仅在 code 模式、且缓冲区以 url( 结尾（允许空白）时进入 url_bare
  defp maybe_enter_url(%Context{css_mode: :code} = ctx, c, rest) do
    ctx = %{ctx | raw_buf: ctx.raw_buf <> <<c>>}

    if url_open?(ctx.raw_buf) do
      feed_literal(%{ctx | css_mode: :url_bare, css_url_pending: true}, rest)
    else
      feed_literal(ctx, rest)
    end
  end

  defp maybe_enter_url(ctx, _c, rest), do: feed_literal(ctx, rest)

  defp url_open?(buf) do
    Regex.match?(~r/url\(\s*$/s, buf)
  end
end

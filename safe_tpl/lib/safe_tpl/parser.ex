defmodule SafeTpl.Parser do
  @moduledoc """
  模板词法 + 语法分析。

  产出 AST 节点：

    * `{:text, binary}`
    * `{:interp, expr_ast, meta_map}`   —— meta 中的 `:escaper` 由 Analyzer 回填
    * `{:if, cond_ast, then_nodes, else_nodes}`
    * `{:for, generator_ast, body_nodes}`

  模板注释 `{# ... #}` 在词法阶段直接丢弃。
  """

  alias SafeTpl.CompileError

  @doc """
  把模板源码解析为节点列表；语法错误抛 CompileError（带行列号）。
  """
  def parse!(source) when is_binary(source) do
    tokens = tokenize(source, 1, 1, [])
    {nodes, rest} = parse_nodes(tokens, [])

    case rest do
      [] ->
        nodes

      [{:block_end, _inner, meta} | _] ->
        raise CompileError,
              message: "unexpected {% #{meta[:inner]} %} without matching opening block",
              line: meta[:line],
              col: meta[:col]
    end
  end

  # ---------- 词法分析 ----------

  defp tokenize(<<>>, _line, _col, acc), do: Enum.reverse(acc)

  # 模板注释 {# ... #}：整体丢弃，但要正确推进行列号
  defp tokenize("{#" <> rest, line, col, acc) do
    case :binary.match(rest, "#}") do
      {offset, len} ->
        comment = binary_part(rest, 0, offset)
        after_c = binary_part(rest, offset + len, byte_size(rest) - offset - len)
        {nl, nc} = advance(comment, line, col)
        tokenize(after_c, nl, nc + 2, acc)

      :nomatch ->
        raise CompileError,
              message: "unterminated template comment {# ... #}",
              line: line,
              col: col
    end
  end

  defp tokenize("{{" <> rest, line, col, acc) do
    case :binary.match(rest, "}}") do
      {offset, len} ->
        inner = binary_part(rest, 0, offset)
        after_i = binary_part(rest, offset + len, byte_size(rest) - offset - len)
        token = {:interp, String.trim(inner), %{line: line, col: col, inner: String.trim(inner)}}
        tokenize(after_i, line, col + 2 + offset + len, [token | acc])

      :nomatch ->
        raise CompileError, message: "unterminated interpolation {{ ... }}", line: line, col: col
    end
  end

  defp tokenize("{%" <> rest, line, col, acc) do
    case :binary.match(rest, "%}") do
      {offset, len} ->
        inner = String.trim(binary_part(rest, 0, offset))
        after_i = binary_part(rest, offset + len, byte_size(rest) - offset - len)
        token = {:block, inner, %{line: line, col: col, inner: inner}}
        tokenize(after_i, line, col + 2 + offset + len, [token | acc])

      :nomatch ->
        raise CompileError, message: "unterminated block {% ... %}", line: line, col: col
    end
  end

  # 普通文本：一路吃到下一个模板分隔符
  defp tokenize(bin, line, col, acc) do
    case next_delim(bin) do
      nil ->
        if acc == [] and bin == "", do: [], else: tokenize(<<>>, line, col, [{:text, bin, %{line: line, col: col}} | acc])

      offset ->
        chunk = binary_part(bin, 0, offset)
        rest = binary_part(bin, offset, byte_size(bin) - offset)
        {nl, nc} = advance(chunk, line, col)
        tokenize(rest, nl, nc, [{:text, chunk, %{line: line, col: col}} | acc])
    end
  end

  defp next_delim(bin), do: next_delim(bin, 0)

  defp next_delim(<<>>, _), do: nil

  for d <- ["{{", "{%", "{#"] do
    defp next_delim(<<unquote(d), _::binary>>, offset), do: offset
  end

  defp next_delim(<<c, rest::binary>>, offset), do: next_delim(rest, offset + byte_size(<<c>>))

  defp advance(bin, line, col) do
    case :binary.matches(bin, "\n") do
      [] ->
        {line, col + byte_size(bin)}

      matches ->
        last = List.last(matches)
        {line + length(matches), byte_size(bin) - (elem(last, 0) + 1) + 1}
    end
  end

  # ---------- 语法分析 ----------

  defp parse_nodes(tokens, acc) do
    case tokens do
      [] ->
        {Enum.reverse(acc), []}

      [{:text, text, _meta} | rest] ->
        parse_nodes(rest, [{:text, text} | acc])

      [{:interp, inner, meta} | rest] ->
        expr = parse_expr!(inner, meta)
        parse_nodes(rest, [{:interp, expr, %{line: meta[:line], col: meta[:col]}} | acc])

      [{:block, "if " <> cond_inner, meta} | rest] ->
        cond_ast = parse_expr!(cond_inner, meta)
        {then_nodes, after_then} = parse_nodes(rest, [])

        {else_nodes, after_else} =
          case after_then do
            [{:block, "else", _} | r2] -> parse_nodes(r2, [])
            _ -> {[], after_then}
          end

        expect_end!(after_else, meta)
        parse_nodes(tl(after_else), [{:if, cond_ast, then_nodes, else_nodes} | acc])

      [{:block, "for " <> gen_inner, meta} | rest] ->
        gen_ast = parse_generator!(gen_inner, meta)
        {body, after_body} = parse_nodes(rest, [])
        expect_end!(after_body, meta)
        parse_nodes(tl(after_body), [{:for, gen_ast, body} | acc])

      [{:block, "end", _} | _] = rest ->
        {Enum.reverse(acc), rest}

      [{:block, "else", _} | _] = rest ->
        {Enum.reverse(acc), rest}

      [{:block, other, meta} | _] ->
        raise CompileError,
              message: "unknown block #{inspect(other)}; only if / for / else / end are supported",
              line: meta[:line],
              col: meta[:col]
    end
  end

  defp expect_end!([{:block, "end", _} | _], _meta), do: :ok

  defp expect_end!([{:block, other, meta} | _], _) do
    raise CompileError,
          message: "expected {% end %}, got {% #{other} %}",
          line: meta[:line],
          col: meta[:col]
  end

  defp expect_end!([], meta) do
    raise CompileError, message: "block is missing its {% end %}", line: meta[:line], col: meta[:col]
  end

  defp parse_expr!(inner, meta) do
    case Code.string_to_quoted(inner) do
      {:ok, ast} ->
        ast

      {:error, {reason, detail}} ->
        raise CompileError,
              message: "invalid expression #{inspect(inner)}: #{format_syntax(reason, detail)}",
              line: meta[:line],
              col: meta[:col]
    end
  end

  defp parse_generator!(inner, meta) do
    # 借用 Elixir 自己的 parser：for x <- xs do ... end
    wrapped = "for " <> inner <> " do :ok end"

    case Code.string_to_quoted(wrapped) do
      {:ok, {:for, _, [generators | _]}} ->
        case generators do
          {:<-, _, [_pattern, _enum]} = gen -> gen
          _ -> raise CompileError, message: "unsupported for-generator: #{inspect(inner)}", line: meta[:line], col: meta[:col]
        end

      {:error, {reason, detail}} ->
        raise CompileError,
              message: "invalid for-generator #{inspect(inner)}: #{format_syntax(reason, detail)}",
              line: meta[:line],
              col: meta[:col]
    end
  end

  defp format_syntax(reason, detail) when is_binary(detail), do: "#{reason} #{detail}"
  defp format_syntax(reason, detail), do: "#{inspect(reason)} #{inspect(detail)}"
end

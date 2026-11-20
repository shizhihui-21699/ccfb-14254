defmodule SafeTpl.Json do
  @moduledoc """
  受限 JSON 编码器，服务于 JS 代码位插值（`js_val`）。

  只接受能安全嵌入 `<script>` 的 JSON 类型：
  binary / atom(含 nil、true、false) / integer / float / list / 字符串键 map 与 keyword。

  额外把 `<`、`>`、U+2028/2029 转义，杜绝 `</script>` 提前闭合与 JS 行分隔符问题。
  tuple / 函数 / pid / reference / 非字符串键 map 一律拒绝。
  """

  alias SafeTpl.RenderError

  def encode!(value), do: IO.iodata_to_binary(encode(value))

  defp encode(nil), do: "null"
  defp encode(true), do: "true"
  defp encode(false), do: "false"

  defp encode(atom) when is_atom(atom), do: encode_string(Atom.to_string(atom))

  defp encode(i) when is_integer(i), do: Integer.to_string(i)

  defp encode(f) when is_float(f) do
    # 非有限浮点（NaN/Inf）在 JSON 中无合法表示：NaN 不等于自身，Inf 绝对值溢出
    if f != f or f > 1.0e308 or f < -1.0e308 do
      raise RenderError, message: "non-finite float cannot be encoded as JS value"
    end

    :erlang.float_to_binary(f, [:short])
  end

  defp encode(bin) when is_binary(bin), do: encode_string(bin)

  defp encode(list) when is_list(list) do
    if Keyword.keyword?(list) do
      encode_object(list)
    else
      ["[", Enum.map_intersperse(list, ",", &encode/1), "]"]
    end
  end

  defp encode(map) when is_map(map) do
    pairs =
      try do
        Enum.map(map, fn
          {k, v} when is_binary(k) -> {k, v}
          {k, v} when is_atom(k) -> {Atom.to_string(k), v}
          {other, _} ->
            raise RenderError, message: "map key #{inspect(other)} cannot be encoded as a JS object key"
        end)
      rescue
        _ ->
          raise RenderError, message: "unsupported map shape for JS encoding"
      end

    encode_object(pairs)
  end

  defp encode(other) do
    raise RenderError, message: "value of type #{typeof(other)} cannot be safely embedded as a JS value"
  end

  defp encode_object(pairs) do
    parts =
      Enum.map(pairs, fn {k, v} ->
        [encode_string(k), ":", encode(v)]
      end)

    ["{", Enum.intersperse(parts, ","), "}"]
  end

  defp encode_string(bin) do
    ["\"", encode_chars(String.to_charlist(bin)), "\""]
  end

  defp encode_chars([]), do: []

  for {cp, rep} <- [
        {?", ~c"\\\""},
        {?\\, ~c"\\\\"},
        {?\b, ~c"\\b"},
        {?\f, ~c"\\f"},
        {?\n, ~c"\\n"},
        {?\r, ~c"\\r"},
        {?\t, ~c"\\t"}
      ] do
    defp encode_chars([unquote(cp) | rest]), do: [unquote(rep) | encode_chars(rest)]
  end

  defp encode_chars([cp | rest]) when cp < 0x20 or cp in [?<, ?>, 0x2028, 0x2029] do
    [["\\u", pad4(cp)] | encode_chars(rest)]
  end

  defp encode_chars([cp | rest]) do
    [<<cp::utf8>> | encode_chars(rest)]
  end

  defp pad4(cp), do: cp |> Integer.to_string(16) |> String.pad_leading(4, "0")

  defp typeof(v) when is_tuple(v), do: "tuple"
  defp typeof(v) when is_function(v), do: "function"
  defp typeof(v) when is_pid(v), do: "pid"
  defp typeof(v) when is_reference(v), do: "reference"
  defp typeof(v) when is_port(v), do: "port"
  defp typeof(_), do: "unsupported"
end

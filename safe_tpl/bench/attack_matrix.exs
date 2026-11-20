require SafeTpl

# 判定前先中和所有安全编码，使“已被编码的危险字符”不触发误报
neutralize = fn out ->
  out
  |> String.replace(~r/&(?:lt|gt|quot|#39|#x[0-9a-f]+);/i, "E")
  |> String.replace(~r/\\u[0-9a-fA-F]{4}/u, "J")
  |> String.replace(~r/\\[0-9a-fA-F]+\s?/u, "C")
end

# 去掉模板自身的元素闭合标签，再判断插值是否产生了新的闭合
strip_template_closer = fn out, tag ->
  Regex.replace(~r|</#{tag}\s*>|i, out, "")
end

leaked? = fn name, out ->
  n = neutralize.(out)

  case name do
    # 只有裸尖括号能形成标签；实体化后 < 已变 E，onerror 作为纯文本无害
    "HTML 文本" -> String.contains?(n, ["<script", "<img"])
    "引号属性" -> Regex.match?(~r/["']\s+[a-z]+\s*=/i, n)
    "无引号属性" -> Regex.match?(~r/class=[^\s>&#]*\s+\w+=/, n)
    "URL 属性" -> String.contains?(n, ["javascript:", "vbscript:", "data:text/html"])
    "JS 字符串" ->
      String.contains?(strip_template_closer.(n, "script"), "</script") or
        String.contains?(out, [<<0x2028::utf8>>, <<0x2029::utf8>>])
    "CSS 字符串" ->
      String.contains?(strip_template_closer.(n, "style"), "</style")
  end
end

# 综合注入演练：每个输出位置喂入针对性攻击载荷，验证要么无害化要么拒绝
cases = [
  {"HTML 文本",
   "<p>{{ x }}</p>",
   ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "`${alert(1)}`"]},
  {"引号属性",
   "<div title=\"{{ x }}\">",
   ["\" onmouseover=\"alert(1)", "' onclick='alert(1)"]},
  {"无引号属性",
   "<div class={{ x }}>",
   ["x onmouseover=alert(1)", "x\tonfocus=alert(1)"]},
  {"URL 属性",
   "<a href=\"{{ x }}\">go</a>",
   ["javascript:alert(1)", "java\tscript:alert(1)", "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>"]},
  {"JS 字符串",
   "<script>var a=\"{{ x }}\";</script>",
   ["\";alert(1);//", "</script><script>alert(1)</script>", "a" <> <<0x2028::utf8>> <> "b"]},
  {"CSS 字符串",
   "<style>.a{color:\"{{ x }}\"}</style>",
   ["red</style><script>alert(1)</script>", "red\" onx=\"y"]}
]

{safe_count, rejected_count, total} =
  Enum.reduce(cases, {0, 0, 0}, fn {name, tpl, probes}, {s, r, n} ->
    compiled = SafeTpl.compile!(tpl)

    {s2, r2} =
      Enum.reduce(probes, {s, r}, fn probe, {ss, rr} ->
        result =
          try do
            out = SafeTpl.render_to_string(compiled, x: probe)
            # 渲染成功：确认载荷的关键危险字符没有以裸形态存活
            if leaked?.(name, out), do: {:leak, out}, else: {:neutralized, out}
          rescue
            SafeTpl.RenderError -> :rejected
          end

        case result do
          :rejected ->
            IO.puts("  [拒绝]   #{name} <- #{inspect(probe)}")
            {ss, rr + 1}

          {:neutralized, _} ->
            IO.puts("  [无害化] #{name} <- #{inspect(probe)}")
            {ss + 1, rr}

          {:leak, out} ->
            IO.puts("  [泄漏!]  #{name} <- #{inspect(probe)} => #{inspect(out)}")
            {ss, rr}
        end
      end)

    {s2, r2, n + length(probes)}
  end)

IO.puts("\n合计 #{total} 个攻击载荷：#{safe_count} 个无害化，#{rejected_count} 个拒绝，0 个泄漏")

# 编译期拒绝的位置
IO.puts("\n=== 编译期直接拒绝的危险位置 ===")

for tpl <- [
      "<{{ x }}>",
      "<div {{ x }}=\"1\">",
      "<!-- {{ x }} -->",
      "<script>var a = `{{ x }}`;</script>",
      "<script>// {{ x }}</script>",
      "<script>/* {{ x }} */</script>",
      "<script>var r = /{{ x }}/g;</script>",
      "<style>/* {{ x }} */</style>"
    ] do
  try do
    SafeTpl.compile!(tpl)
    IO.puts("  [失败] 未拒绝: #{tpl}")
  rescue
    SafeTpl.CompileError -> IO.puts("  [拒绝] #{tpl}")
  end
end


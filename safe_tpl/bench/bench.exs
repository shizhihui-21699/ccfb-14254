require SafeTpl

# 一个覆盖多种上下文的真实页面模板
page_template = """
<article class="{{ cls }}">
  <h1>{{ title }}</h1>
  <a href="{{ link }}">{{ anchor }}</a>
  <img src="{{ img }}" alt="{{ alt }}">
  <script>
    var config = {{ config }};
    var userId = "{{ user_id }}";
  </script>
  <style>.box { background: url("{{ bg }}"); color: "{{ color }}"; }</style>
  <ul>
    {% for item <- items %}<li>{{ item }}</li>{% end %}
  </ul>
</article>
"""

compiled = SafeTpl.compile!(page_template)

assigns = [
  cls: "post featured",
  title: "Hello & welcome <world>",
  link: "/search?q=elixir&lang=zh",
  anchor: "click \"here\"",
  img: "/assets/logo.png",
  alt: "a \"nice\" logo",
  config: %{"theme" => "dark", "limit" => 10, "features" => ["a", "b"]},
  user_id: "user-1234",
  bg: "/img/bg.png",
  color: "#3366cc",
  items: ["first <x>", "second", "third & co"]
]

# 统一 HTML 转义基线：模拟旧框架“所有位置只做一次 HTML 转义”
defmodule Baseline do
  def html_escape(nil), do: ""
  def html_escape(v) when is_binary(v), do: SafeTpl.Escapers.html_text(v)
  def html_escape(v), do: html_escape(to_string(v))

  def render(a) do
    items = for item <- a[:items], do: ["<li>", html_escape(item), "</li>"]

    [
      "<article class=\"", html_escape(a[:cls]), "\">\n  <h1>",
      html_escape(a[:title]), "</h1>\n  <a href=\"", html_escape(a[:link]),
      "\">", html_escape(a[:anchor]), "</a>\n  <img src=\"",
      html_escape(a[:img]), "\" alt=\"", html_escape(a[:alt]),
      "\">\n  <script>\n    var config = ", html_escape(inspect(a[:config])),
      ";\n    var userId = \"", html_escape(a[:user_id]),
      "\";\n  </script>\n  <style>.box { background: url(\"",
      html_escape(a[:bg]), "\"); color: \"", html_escape(a[:color]),
      "\"; }</style>\n  <ul>\n    ",
      items,
      "\n  </ul>\n</article>\n"
    ]
  end
end

# 预热：确保编译与首次 JIT 路径都已走过
_ = SafeTpl.render(compiled, assigns)
_ = Baseline.render(assigns)
IO.puts("warmup done\n")

n = 200_000

{t_safe, _} =
  :timer.tc(fn ->
    Enum.each(1..n, fn _ -> SafeTpl.render(compiled, assigns) end)
  end)

{t_base, _} =
  :timer.tc(fn ->
    Enum.each(1..n, fn _ -> Baseline.render(assigns) end)
  end)

safe_us = t_safe / n
base_us = t_base / n

IO.puts("渲染次数: #{n}")
IO.puts("本引擎（上下文感知）单次: #{:erlang.float_to_binary(safe_us, [decimals: 3])} µs")
IO.puts("基线（统一HTML转义）单次: #{:erlang.float_to_binary(base_us, [decimals: 3])} µs")
IO.puts("相对开销: #{:erlang.float_to_binary(safe_us / base_us * 100, [decimals: 1])}% （越接近 100% 越好）")

# 正确性对比：同一份攻击数据，基线挡不住的场景
attack =
  Keyword.merge(assigns,
    link: "javascript:alert(1)",
    user_id: "</script><script>alert(1)</script>"
  )

IO.puts("\n=== 安全性对比（攻击数据）===")

try do
  SafeTpl.render_to_string(compiled, attack)
  IO.puts("本引擎 link: 未拦截（意外）")
rescue
  SafeTpl.RenderError -> IO.puts("本引擎 link: 已拒绝 javascript: 协议 ✓")
end

base_out = Baseline.render(attack) |> IO.iodata_to_binary()

if String.contains?(base_out, "javascript:alert(1)"),
  do: IO.puts("基线 link: 原样输出 javascript: 协议 ✗（XSS）"),
  else: IO.puts("基线 link: 已转义")

if String.contains?(base_out, "</script><script>"),
  do: IO.puts("基线 user_id: 脚本注入成功 ✗（XSS）"),
  else: IO.puts("基线 user_id: 未注入")

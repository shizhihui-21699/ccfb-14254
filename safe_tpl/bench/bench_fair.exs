require SafeTpl

# 公平对照：两个模板结构、插值数量完全相同，只比较引擎开销
# 纯 HTML 上下文（基线也能正确处理的场景），隔离“引擎框架成本”
html_template = """
<article class="{{ cls }}">
  <h1>{{ title }}</h1>
  <a href="{{ link }}">{{ anchor }}</a>
  <img src="{{ img }}" alt="{{ alt }}">
  <p>{{ body }}</p>
  <span data-id="{{ id }}">{{ label }}</span>
  <ul>
    {% for item <- items %}<li>{{ item }}</li>{% end %}
  </ul>
</article>
"""

compiled = SafeTpl.compile!(html_template)

assigns = [
  cls: "post featured",
  title: "Hello & welcome <world>",
  link: "/search?q=elixir&lang=zh",
  anchor: "click here",
  img: "/assets/logo.png",
  alt: "a nice logo",
  body: "text & more <stuff>",
  id: "id-42",
  label: "my label",
  items: ["first", "second", "third"]
]

defmodule FairBaseline do
  def he(v), do: SafeTpl.Escapers.html_text(v)

  def render(a) do
    items = for item <- a[:items], do: ["<li>", he(item), "</li>"]

    [
      "<article class=\"", he(a[:cls]), "\">\n  <h1>", he(a[:title]),
      "</h1>\n  <a href=\"", he(a[:link]), "\">", he(a[:anchor]),
      "</a>\n  <img src=\"", he(a[:img]), "\" alt=\"", he(a[:alt]),
      "\">\n  <p>", he(a[:body]), "</p>\n  <span data-id=\"", he(a[:id]),
      "\">", he(a[:label]), "</span>\n  <ul>\n    ", items,
      "\n  </ul>\n</article>\n"
    ]
  end
end

_ = SafeTpl.render(compiled, assigns)
_ = FairBaseline.render(assigns)

n = 500_000

{t_safe, _} = :timer.tc(fn -> Enum.each(1..n, fn _ -> SafeTpl.render(compiled, assigns) end) end)
{t_base, _} = :timer.tc(fn -> Enum.each(1..n, fn _ -> FairBaseline.render(assigns) end) end)

safe_us = t_safe / n
base_us = t_base / n

IO.puts("公平对照（相同结构、9 个插值 + for，纯 HTML 上下文）")
IO.puts("渲染次数: #{n}")
IO.puts("本引擎单次:   #{:erlang.float_to_binary(safe_us, [decimals: 3])} µs")
IO.puts("手写基线单次: #{:erlang.float_to_binary(base_us, [decimals: 3])} µs")
IO.puts("框架开销比: #{:erlang.float_to_binary(safe_us / base_us * 100, [decimals: 1])}%")
IO.puts("每个插值额外成本: #{:erlang.float_to_binary((safe_us - base_us) / 9, [decimals: 3])} µs")

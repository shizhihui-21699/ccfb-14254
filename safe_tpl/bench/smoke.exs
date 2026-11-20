require SafeTpl

template = """
<a href="{{ url }}">{{ name }}</a>
<script>var x = "{{ data }}";</script>
<div class="{{ cls }}" onclick="{{ handler }}">x</div>
<style>.a { background: url("{{ bg }}"); color: "{{ color }}"; }</style>
"""

t = SafeTpl.compile!(template)

out =
  SafeTpl.render_to_string(t,
    # 合法相对/绝对 URL 正常输出
    url: "/search?q=1&x=2",
    name: "<script>alert(1)</script>",
    data: "\";alert(1);//",
    cls: "\" onmouseover=\"alert(1)",
    handler: "alert(1)",
    bg: "/img/logo.png",
    color: "red\"evil"
  )

IO.puts("=== 正常渲染（攻击载荷已被上下文转义无害化）===")
IO.puts(out)
IO.puts("\n=== 编译期选定的转义器 ===")
IO.inspect(t.escapes)

IO.puts("\n=== 危险 URL 在渲染期被拒绝 ===")

for bad <- ["javascript:alert(1)", "java\tscript:alert(1)", "vbscript:msgbox(1)"] do
  try do
    SafeTpl.render_to_string(t, url: bad, name: "x", data: "x", cls: "x", handler: "x", bg: "x", color: "x")
    IO.puts("FAIL: #{inspect(bad)} 未被拦截")
  rescue
    SafeTpl.RenderError -> IO.puts("已拒绝: #{inspect(bad)}")
  end
end

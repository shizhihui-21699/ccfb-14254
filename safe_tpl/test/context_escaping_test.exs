defmodule SafeTpl.ContextEscapingTest do
  use ExUnit.Case, async: true
  import SafeTpl.XssCase

  describe "HTML 文本节点 (html_text)" do
    test "脚本标签与尖括号被实体化" do
      for probe <- html_probes() do
        out = render("<p>{{ x }}</p>", x: probe)
        assert active_dangers(out) == [], "probe #{inspect(probe)} produced danger: #{inspect(out)}"
        refute out =~ ~r{<script>}, "raw script leaked from #{inspect(probe)}"
      end
    end

    test "转义器在编译期被选为 html_text" do
      assert SafeTpl.compile!("<p>{{ x }}</p>").escapes == [:html_text]
    end

    test "正常文本原样保留" do
      assert render("<p>{{ x }}</p>", x: "hello & goodbye") == "<p>hello &amp; goodbye</p>"
    end
  end

  describe "引号包裹的属性值 (html_attr)" do
    test "引号逃逸与事件处理器注入被挡" do
      for probe <- html_probes() do
        out = render("<div class=\"{{ x }}\">z</div>", x: probe)
        assert active_dangers(out) == [], "probe #{inspect(probe)} -> #{inspect(out)}"
      end
    end

    test "单双引号属性都安全" do
      out1 = render("<a title=\"{{ x }}\">", x: "\"onclick=\"alert(1)")
      assert out1 =~ "&quot;"
      # 引号被实体化后，onclick= 只是值内文本，不构成真实属性
      assert active_dangers(out1) == []

      out2 = render("<a title='{{ x }}'>", x: "'onclick='alert(1)")
      assert out2 =~ "&#39;"
      assert active_dangers(out2) == []
    end

    test "布尔/数值类型可渲染" do
      assert render("<b>{{ x }}</b>", x: 42) == "<b>42</b>"
      assert render("<b>{{ x }}</b>", x: true) == "<b>true</b>"
    end
  end

  describe "无引号属性值 (html_attr_uq)" do
    test "空白截断注入被严格白名单挡下" do
      for probe <- html_probes() do
        out = render("<div class={{ x }}>z</div>", x: probe)
        refute out =~ ~r/class=[^\s>]*\s+on\w+=/i, "probe #{inspect(probe)} -> #{inspect(out)}"
        assert active_dangers(out) == []
      end
    end

    test "危险 codepoint 全部数字字符引用" do
      out = render("<b x={{ v }}>", v: "a b\"c<d")
      refute out =~ ~r/x=a b/
      assert out =~ ~r/&#x/
    end
  end

  describe "URL 属性 (url_filter)" do
    test "可执行协议被拒绝或无害化" do
      assert_url_safe("<a href=\"{{ x }}\">go</a>", :x, url_probes())
    end

    test "javascript: 直接渲染期报错" do
      assert_render_error("<a href=\"{{ x }}\">go</a>", x: "javascript:alert(1)")
    end

    test "tab/换行/NUL 混淆的协议被剥离后仍识别并拒绝" do
      assert_render_error("<a href=\"{{ x }}\">go</a>", x: "java\tscript:alert(1)")
      assert_render_error("<a href=\"{{ x }}\">go</a>", x: "java\nscript:alert(1)")
    end

    test "data: 仅允许白名单图片类型，svg 被拒" do
      assert_render_error("<a href=\"{{ x }}\">go</a>",
        x: "data:image/svg+xml;base64,PHN2Zz4=")

      out = render("<img src=\"{{ x }}\">", x: "data:image/png;base64,iVBORw0KGgo=")
      assert out =~ "data:image/png;base64"
    end

    test "良性相对/绝对 URL 正常输出且做 HTML 转义" do
      assert render("<a href=\"{{ x }}\">go</a>", x: "/a?b=1&c=2") ==
               "<a href=\"/a?b=1&amp;c=2\">go</a>"

      assert render("<a href=\"{{ x }}\">go</a>", x: "https://example.com/") =~
               "https://example.com/"
    end

    test "URL 属性中的插值：值首走 scheme 过滤，中间片段走百分号编码" do
      assert SafeTpl.compile!("<a href=\"{{ x }}\">go</a>").escapes == [:url_filter_html]
      assert SafeTpl.compile!("<a href=\"/q?x={{ x }}\">go</a>").escapes == [:url_segment_html]
    end
  end

  describe "<script> 内 JS 字符串 (js_str)" do
    test "引号闭合与语句注入被 unicode 转义挡下" do
      for probe <- js_probes() do
        out = render("<script>var a = \"{{ x }}\";</script>", x: probe)
        assert js_context_safe?(out), "probe #{inspect(probe)} -> #{inspect(out)}"
        refute raw_element_closer_leaked?(out, "script"),
               "probe #{inspect(probe)} leaked raw closer: #{inspect(out)}"
      end
    end

    test "转义器选择 js_str 且 < 被 unicode 编码" do
      t = SafeTpl.compile!("<script>var a = '{{ x }}';</script>")
      assert t.escapes == [:js_str]
      out = render("<script>var a = '{{ x }}';</script>", x: "<b>")
      # < 被 unicode 转义（hex 大小写不敏感），杜绝裸尖括号
      assert Regex.match?(~r/\\u003c/i, out)
    end

    test "U+2028/U+2029 行分隔符被转义" do
      out = render("<script>var a = \"{{ x }}\";</script>", x: "a\u2028b")
      refute out =~ <<0x2028::utf8>>
    end
  end

  describe "<script> 内 JS 代码位 (js_val)" do
    test "只接受 JSON 安全值" do
      assert render("<script>var a = {{ x }};</script>", x: 42) =~ "var a = 42;"
      assert render("<script>var a = {{ x }};</script>", x: "hi") =~ "var a = \"hi\";"
      assert render("<script>var a = {{ x }};</script>", x: [1, 2]) =~ "var a = [1,2];"
      assert render("<script>var a = {{ x }};</script>", x: %{"k" => "v"}) =~ "\"k\":\"v\""
    end

    test "字符串内的 </script> 被 JSON 编码无害化" do
      out = render("<script>var a = {{ x }};</script>",
        x: "</script><img src=x onerror=alert(1)>")
      assert js_context_safe?(out)
      assert Regex.match?(~r/\\u003c/i, out)
    end

    test "tuple/函数等不可安全编码的值渲染期报错" do
      assert_render_error("<script>var a = {{ x }};</script>", x: {:foo, :bar})
      assert_render_error("<script>var a = {{ x }};</script>", x: fn -> :ok end)
    end

    test "转义器在编译期选择 js_val" do
      assert SafeTpl.compile!("<script>var a = {{ x }};</script>").escapes == [:js_val]
    end
  end

  describe "JS 危险词法位置（编译期拒绝）" do
    test "模板字符串内插值报错" do
      assert_compile_error("<script>var a = `{{ x }}`;</script>")
    end

    test "行注释内插值报错" do
      assert_compile_error("<script>// {{ x }}\nvar b=1;</script>")
    end

    test "块注释内插值报错" do
      assert_compile_error("<script>/* {{ x }} */\nvar b=1;</script>")
    end

    test "正则字面量内插值报错" do
      assert_compile_error("<script>var r = /{{ x }}/g;</script>")
    end
  end

  describe "JS URL 接收位 (js_str_url / js_val_url)" do
    test "location 赋值处的字符串做 scheme 过滤" do
      tpl = "<script>location = \"{{ x }}\";</script>"
      assert SafeTpl.compile!(tpl).escapes == [:js_str_url]
      assert_render_error(tpl, x: "javascript:alert(1)")
      out = render(tpl, x: "/home")
      assert out =~ "/home"
    end

    test "fetch( 调用处识别为 URL sink" do
      tpl = "<script>fetch(\"{{ x }}\");</script>"
      assert SafeTpl.compile!(tpl).escapes == [:js_str_url]
      assert_render_error(tpl, x: "javascript:alert(1)")
    end
  end

  describe "<style> CSS 字符串 (css_str)" do
    test "引号逃逸与标签闭合被 hex 转义挡下" do
      for probe <- css_probes() do
        out = render("<style>.a { color: \"{{ x }}\"; }</style>", x: probe)
        assert active_dangers(out) == [], "probe #{inspect(probe)} -> #{inspect(out)}"
        refute raw_element_closer_leaked?(out, "style"),
               "probe #{inspect(probe)} leaked raw closer: #{inspect(out)}"
      end
    end

    test "转义器选择 css_str" do
      assert SafeTpl.compile!("<style>.a{color:'{{ x }}'}</style>").escapes == [:css_str]
    end
  end

  describe "CSS 声明值代码位 (css_val)" do
    test "expression/javascript 等危险构造被拒绝" do
      assert_render_error("<style>.a{width:{{ x }}}</style>", x: "expression(alert(1))")

      assert_render_error("<style>.a{width:{{ x }}}</style>",
        x: "red; background:url(javascript:alert(1))")
    end

    test "良性值通过白名单" do
      out = render("<style>.a{color:{{ x }}}</style>", x: "red")
      assert out =~ "red"
    end
  end

  describe "CSS url(...) (url_filter_css)" do
    test "javascript 协议被拒绝" do
      assert_render_error("<style>.a{background:url({{ x }})}</style>",
        x: "javascript:alert(1)")
    end

    test "带引号 url 形式同样过滤" do
      t = SafeTpl.compile!("<style>.a{background:url(\"{{ x }}\")}</style>")
      assert t.escapes == [:url_filter_css_str]
      out = render("<style>.a{background:url(\"{{ x }}\")}</style>", x: "/img/a.png")
      assert out =~ "/img/a.png"
    end
  end

  describe "CSS 注释（编译期拒绝）" do
    test "块注释内插值报错" do
      assert_compile_error("<style>/* {{ x }} */ .a{color:red}</style>")
    end
  end

  describe "on* 事件处理器属性 (js_val_html)" do
    test "属性值按 JS 语义编码后再 HTML 转义" do
      t = SafeTpl.compile!("<button onclick=\"{{ x }}\">b</button>")
      assert t.escapes == [:js_val_html]
      out = render("<button onclick=\"{{ x }}\">b</button>", x: "alert(1)")
      refute out =~ ~r/onclick=""[^>]/
      assert active_dangers(out) == []
    end

    test "字符串载荷里的引号被双重编码挡住" do
      out = render("<button onclick=\"{{ x }}\">b</button>", x: "\");alert(1);//")
      assert active_dangers(out) == []
    end
  end

  describe "style 属性 (css_val_html)" do
    test "危险 CSS 被策略拒绝" do
      assert_render_error("<div style=\"{{ x }}\">d</div>",
        x: "background:url(javascript:alert(1))")
    end

    test "良性声明通过，冒号等做 CSS hex 转义且整体再 HTML 转义" do
      out = render("<div style=\"{{ x }}\">d</div>", x: "color:red")
      # color 与 red 保留，冒号被 CSS hex 转义（浏览器解析后仍是 color:red）
      assert out =~ "color"
      assert out =~ "red"
      assert out =~ "\\3A "
    end
  end

  describe "无法安全处理的 HTML 位置（编译期拒绝）" do
    test "标签名位置报错" do
      assert_compile_error("<{{ x }}>y</div>")
    end

    test "属性名位置报错" do
      assert_compile_error("<div {{ x }}=\"v\">y</div>")
    end

    test "HTML 注释内报错" do
      assert_compile_error("<!-- {{ x }} -->")
    end

    test "DOCTYPE 内报错" do
      assert_compile_error("<!DOCTYPE {{ x }}>")
    end
  end

  describe "条件分支的环境一致性" do
    test "两分支环境一致时正常编译" do
      tpl = "<p>{% if show %}<b>{{ a }}</b>{% else %}<i>{{ a }}</i>{% end %}</p>"
      t = SafeTpl.compile!(tpl)
      assert Enum.all?(t.escapes, &(&1 == :html_text))
      out = render(tpl, show: true, a: "<x>")
      assert out == "<p><b>&lt;x&gt;</b></p>"
    end

    test "分支导致后续插值环境不确定时报错" do
      # then 分支停在引号属性值内，else 分支已闭合回到属性名状态：环境不一致
      assert_compile_error("<div {% if x %}title=\"{{ a }}{% else %}title=\"{{ b }}\"{% end %}>")
    end

    test "两个分支同名属性且都完整闭合时可以安全合并" do
      tpl = "<div {% if x %}class=\"{{ a }}\"{% else %}class=\"{{ b }}\"{% end %}>z</div>"
      t = SafeTpl.compile!(tpl)
      assert Enum.all?(t.escapes, &(&1 == :html_attr))
    end

    test "for 循环体改变环境且未还原时报错" do
      assert_compile_error("<p>{% for i <- items %}<b>{{ i }}{% end %}</p>")
    end

    test "for 循环体环境平衡时正常" do
      tpl = "<ul>{% for i <- items %}<li>{{ i }}</li>{% end %}</ul>"
      out = render(tpl, items: ["<a>", "b"])
      assert out == "<ul><li>&lt;a&gt;</li><li>b</li></ul>"
    end
  end

  describe "多层嵌套与上下文切换" do
    test "script 闭合后正确回到 HTML 文本环境" do
      tpl = "<script>var a=1;</script><p>{{ x }}</p>"
      assert SafeTpl.compile!(tpl).escapes == [:html_text]
      out = render(tpl, x: "<b>")
      assert out == "<script>var a=1;</script><p>&lt;b&gt;</p>"
    end

    test "style 闭合后正确回到属性环境" do
      tpl = "<style>.a{color:red}</style><a title=\"{{ x }}\">y</a>"
      assert SafeTpl.compile!(tpl).escapes == [:html_attr]
    end

    test "深层嵌套标签栈正确维护" do
      tpl = "<div><section><p>{{ x }}</p></section></div>"
      assert render(tpl, x: "a&b") == "<div><section><p>a&amp;b</p></section></div>"
    end

    test "script 内字符串与代码位混合，各自选对转义器" do
      tpl = "<script>var s=\"{{ a }}\", n={{ b }};</script>"
      assert SafeTpl.compile!(tpl).escapes == [:js_str, :js_val]
    end
  end

  describe "模板注释" do
    test "{# #} 内容被丢弃且不影响环境" do
      assert render("<p>{# note #}{{ x }}</p>", x: "a") == "<p>a</p>"
    end
  end
end

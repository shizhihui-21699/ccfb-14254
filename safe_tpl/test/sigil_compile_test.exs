defmodule SafeTpl.SigilCompileTest do
  use ExUnit.Case

  defmodule Page do
    require SafeTpl

    def compiled do
      SafeTpl.sigil_T(<<"<a href=\"{{ url }}\">{{ name }}</a>">>, [])
    end

    def render(assigns), do: SafeTpl.render_to_string(compiled(), assigns)
  end

  test "sigil 编译期完成上下文分析，运行期直接渲染" do
    assert Page.render(url: "/x", name: "a&b") ==
             ~s(<a href="/x">a&amp;b</a>)
  end

  test "sigil 在编译期拒绝不安全位置（标签名插值）" do
    ast =
      quote do
        require SafeTpl
        SafeTpl.sigil_T(<<"<{{ x }}>">>, [])
      end

    assert_raise CompileError, ~r/unsafe position/, fn ->
      Code.eval_quoted(ast, [], __ENV__)
    end
  end

  test "sigil 在编译期拒绝 JS 模板字符串内插值" do
    ast =
      quote do
        require SafeTpl
        SafeTpl.sigil_T(<<"<script>var a = `{{ x }}`;</script>">>, [])
      end

    assert_raise CompileError, ~r/template literal/, fn ->
      Code.eval_quoted(ast, [], __ENV__)
    end
  end
end

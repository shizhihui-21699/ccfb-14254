defmodule SafeTpl do
  @moduledoc ~S"""
  SafeTpl —— 编译期上下文感知自动转义模板引擎。

  模板语法（默认分隔符 `{{ }}`，与 Elixir 自身插值无关）：

      {{ expr }}        插值点；转义方式由该点的**语法环境**在编译期决定
      {% if cond %} ... {% else %} ... {% end %}
      {% for item <- list %} ... {% end %}
      {# 注释 #}        模板注释，渲染时丢弃

  用法（推荐：sigil 在编译期完成词法/语法分析、上下文状态机分析、转义函数选择，
  运行时只剩 iodata 拼接与一次转义函数调用）：

      defmodule Page do
        require SafeTpl
        def render(assigns) do
          SafeTpl.sigil_T(~s|<a href="{{ url }}">{{ name }}</a>|, []) |> SafeTpl.render(assigns)
        end
      end

  也可以在运行时调用 `compile!/1`（编译结果可缓存复用）。

  安全模型概述见 `SafeTpl.Context` 与 `SafeTpl.Escapers` 的模块文档。
  """

  @doc """
  编译期 sigil：`~T|...|`。返回一个编译后的模板结构（%SafeTpl.Compiled{}），
  模板词法/语法错误与“无法安全处理的输出位置”错误都会在**编译期**抛出。
  """
  defmacro sigil_T({:<<>>, _meta, [binary]}, _modifiers) when is_binary(binary) do
    compiled =
      try do
        SafeTpl.compile!(binary)
      rescue
        e in SafeTpl.CompileError ->
          # 编译期调用：升级为 Elixir 编译错误，让构建直接失败并指向模板
          raise CompileError, description: e.message
      end

    quote generated: true do
      unquote(Macro.escape(compiled))
    end
  end

  # 带插值的字符串不允许：插值发生在 Elixir 层，会绕过上下文分析
  defmacro sigil_T({:<<>>, _meta, parts}, _modifiers) do
    raise ArgumentError,
          "~T 不支持字符串插值（#{inspect(parts)}）；模板数据必须通过 render/2 的 assigns 传入"
  end

  @doc "编译模板字符串，失败时抛出 SafeTpl.CompileError。"
  def compile!(source) when is_binary(source) do
    nodes = SafeTpl.Parser.parse!(source)
    SafeTpl.Analyzer.analyze!(nodes)
  end

  @doc "用 assigns 渲染已编译模板，返回 iodata（可直接交给 Plug/HTTP 层）。"
  def render(%SafeTpl.Compiled{fun: fun}, assigns)
      when is_function(fun, 1) and (is_list(assigns) or is_map(assigns)) do
    fun.(assigns)
  end

  @doc "渲染并返回字符串。"
  def render_to_string(compiled, assigns) do
    compiled |> render(assigns) |> IO.iodata_to_binary()
  end

  @doc """
  编译期辅助：把模板中用户表达式里的裸变量替换为 `assign(assigns, :name)` 访问，
  使渲染函数只需一个 `assigns` 入参。
  """
  def assign(assigns, key) when is_atom(key) do
    case assigns do
      %{^key => v} -> v
      _ when is_list(assigns) -> Keyword.get(assigns, key)
      _ -> Map.get(assigns, Atom.to_string(key))
    end
  end
end

defmodule SafeTpl.CompileError do
  @moduledoc "模板编译期错误（语法错误或输出位置无法安全转义）。"
  defexception [:message, :line, :col]

  @impl true
  def message(%__MODULE__{message: msg, line: nil}), do: msg

  def message(%__MODULE__{message: msg, line: line, col: col}) do
    "#{msg} (at line #{line}, col #{col})"
  end
end

defmodule SafeTpl.RenderError do
  @moduledoc "渲染期安全错误（如 js_val 遇到不可编码类型、CSS 值未通过校验）。"
  defexception [:message]
end

defmodule SafeTpl.Compiled do
  @moduledoc false
  @enforce_keys [:fun, :fun_ast]
  defstruct [:fun, :fun_ast, :source, :escapes]
end

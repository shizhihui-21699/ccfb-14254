defmodule SafeTpl.Analyzer do
  @moduledoc """
  编译期第二阶段：在 Parser 产出的 AST 上驱动 `SafeTpl.Context` 状态机，

  1. 为每个插值点按**当时的语法环境**选定转义器并回填 `meta.escaper`；
  2. 对 `if` / `for` 做环境一致性校验（分支结束环境必须与进入环境相同）；
  3. 把整棵树编译成一个只接收 `assigns` 的渲染函数 AST（输出 iodata）。

  运行时没有任何状态机判断：转义器是编译期常量，渲染=递归 iodata 拼接。
  """

  alias SafeTpl.{Compiled, Context}

  @doc """
  分析 + 代码生成，返回 %Compiled{}。

  渲染函数通过 `Code.compile_quoted/2` 编译进一个**动态具名模块**而非 eval 闭包：
  eval 出来的匿名闭包无法被 JIT 内联，实测慢约 10 倍；具名模块函数走正常编译
  流水线，性能与源码手写函数一致。
  """
  def analyze!(nodes) do
    {nodes2, _ctx} = walk(nodes, %Context{})
    fun_ast = build_fun(nodes2)
    mod = unique_module()
    render_fun = build_module_fun(fun_ast)
    Code.compile_quoted(module_ast(mod, render_fun), Atom.to_string(mod) <> ".ex")
    %Compiled{fun: &mod.render/1, fun_ast: fun_ast, source: nil, escapes: collect(nodes2, [])}
  end

  # 用计数器生成唯一模块名（避免 {:current_stacktrace} 之外的时间依赖）
  @counter_key {__MODULE__, :module_counter}
  defp unique_module do
    n = :persistent_term.get(@counter_key, 0) + 1
    :persistent_term.put(@counter_key, n)
    Module.concat(SafeTpl.CompiledModules, "Template#{n}")
  end

  defp module_ast(mod, render_fun) do
    quote do
      defmodule unquote(mod) do
        unquote(render_fun)
      end
    end
  end

  # 把 fn assigns -> body 提升为 def render(assigns), do: body
  defp build_module_fun({:fn, _, [{:->, _, [[{:assigns, am, nil}], body]}]}) do
    {:def, [generated: true],
     [
       {:render, [generated: true], [{:assigns, am, nil}]},
       [do: body]
     ]}
  end

  # ---------- AST 遍历 + 上下文推进 ----------

  defp walk(nodes, ctx) when is_list(nodes) do
    Enum.map_reduce(nodes, ctx, fn node, acc -> walk_node(node, acc) end)
  end

  defp walk_node({:text, text}, ctx) do
    {{:text, text}, Context.feed_text(ctx, text, %{})}
  end

  defp walk_node({:interp, expr, meta}, ctx) do
    escaper = escaper_for(ctx, meta)
    {{:interp, expr, Map.put(meta, :escaper, escaper)}, ctx}
  end

  defp walk_node({:if, cond_ast, then_nodes, else_nodes}, ctx) do
    {then2, ctx_then} = walk(then_nodes, ctx)
    {else2, ctx_else} = walk(else_nodes, ctx)
    merged = Context.merge_contexts!(ctx_then, ctx_else, %{})
    {{:if, cond_ast, then2, else2}, merged}
  end

  defp walk_node({:for, {:<-, m, [_pattern, _enum]} = gen, body}, ctx) do
    {body2, ctx_body} = walk(body, ctx)

    # 循环体可能执行零次：结束环境必须等于进入环境，
    # 否则循环后的插值点在“执行/不执行”两条路径下环境不同。
    _ = Context.merge_contexts!(ctx, ctx_body, %{line: m[:line], col: m[:column] || 1})

    {{:for, gen, body2}, ctx}
  end

  defp escaper_for(%Context{state: :script} = ctx, meta) do
    SafeTpl.JsScanner.escaper_for(ctx, ctx.raw_buf, meta)
  end

  defp escaper_for(%Context{state: :style} = ctx, meta) do
    SafeTpl.CssScanner.escaper_for(ctx, ctx.raw_buf, meta)
  end

  defp escaper_for(ctx, meta), do: Context.escaper_for_interp(ctx, meta)

  # ---------- 变量重写：裸变量 -> SafeTpl.assign(assigns, key) ----------

  defp do_rewrite({name, _meta, nil} = node, scope) when is_atom(name) do
    if Map.has_key?(scope, name) or special_form?(name) do
      node
    else
      m = [generated: true]

      {{:., m, [{:__aliases__, m, [:SafeTpl]}, :assign]}, m,
       [{:assigns, m, nil}, name]}
    end
  end

  # for 生成器引入新绑定
  defp do_rewrite({:for, m, clauses}, scope) do
    {clauses2, _} =
      Enum.map_reduce(clauses, scope, fn
        {:<-, gm, [pattern, enum]}, acc ->
          enum2 = do_rewrite(enum, acc)
          {{:<-, gm, [pattern, enum2]}, collect_pattern_vars(pattern, acc)}

        {:do, body}, acc ->
          {{:do, do_rewrite(body, acc)}, acc}

        other, acc ->
          {do_rewrite(other, acc), acc}
      end)

    {:for, m, clauses2}
  end

  defp do_rewrite({:case, m, [expr, [do: clauses]]}, scope) do
    expr2 = do_rewrite(expr, scope)

    clauses2 =
      Enum.map(clauses, fn {:->, cm, [patterns, body]} ->
        scope2 = Enum.reduce(patterns, scope, &collect_pattern_vars(&1, &2))
        {:->, cm, [patterns, do_rewrite(body, scope2)]}
      end)

    {:case, m, [expr2, [do: clauses2]]}
  end

  defp do_rewrite({fun, m, args}, scope) when is_list(args) do
    {fun, m, Enum.map(args, &do_rewrite(&1, scope))}
  end

  defp do_rewrite({left, right}, scope), do: {do_rewrite(left, scope), do_rewrite(right, scope)}
  defp do_rewrite(list, scope) when is_list(list), do: Enum.map(list, &do_rewrite(&1, scope))
  defp do_rewrite(other, _scope), do: other

  defp collect_pattern_vars(pattern, scope) do
    {_, scope2} =
      Macro.prewalk(pattern, scope, fn
        {name, _, nil} = n, acc when is_atom(name) and name != :_ -> {n, Map.put(acc, name, true)}
        n, acc -> {n, acc}
      end)

    scope2
  end

  defp special_form?(name) do
    name in [:for, :case, :with, :if, :unless, :cond, :fn, :&, :^, :in, :when, :and, :or, :not, :_]
  end

  # ---------- 渲染函数代码生成（携带变量作用域）----------

  defp build_fun(nodes) do
    quote generated: true do
      fn unquote({:assigns, [generated: true], nil}) ->
        unquote(build_iolist(nodes, %{}))
      end
    end
  end

  defp build_iolist(nodes, scope), do: Enum.map(nodes, &build_part(&1, scope))

  defp build_part({:text, text}, _scope), do: text

  defp build_part({:interp, expr, %{escaper: escaper}}, scope) do
    # escaper 是编译期确定的 atom，直接生成静态远程调用（避免 apply/3 的动态分派）
    m = [generated: true]

    {{:., m, [{:__aliases__, m, [:SafeTpl, :Escapers]}, escaper]}, m,
     [do_rewrite(expr, scope)]}
  end

  defp build_part({:if, cond_ast, then_nodes, []}, scope) do
    quote generated: true do
      if unquote(do_rewrite(cond_ast, scope)) do
        unquote(build_iolist(then_nodes, scope))
      else
        []
      end
    end
  end

  defp build_part({:if, cond_ast, then_nodes, else_nodes}, scope) do
    quote generated: true do
      if unquote(do_rewrite(cond_ast, scope)) do
        unquote(build_iolist(then_nodes, scope))
      else
        unquote(build_iolist(else_nodes, scope))
      end
    end
  end

  defp build_part({:for, {:<-, _gm, [pattern, enum_ast]}, body}, scope) do
    inner_scope = collect_pattern_vars(pattern, scope)

    quote generated: true do
      for unquote(pattern) <- unquote(do_rewrite(enum_ast, scope)) do
        unquote(build_iolist(body, inner_scope))
      end
    end
  end

  defp collect([], acc), do: Enum.reverse(acc)
  defp collect([h | t], acc), do: collect(t, collect_node(h, acc))

  defp collect_node({:interp, _, %{escaper: e}}, acc), do: [e | acc]
  defp collect_node({:if, _, a, b}, acc), do: collect(b, collect(a, acc))
  defp collect_node({:for, _, body}, acc), do: collect(body, acc)
  defp collect_node(_, acc), do: acc
end

defmodule SafeTpl.MixProject do
  use Mix.Project

  def project do
    [
      app: :safe_tpl,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: [],
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end

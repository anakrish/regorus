# Regorusrb

**Regorus** is

  - *Rego*-*Rus(t)*  - A fast, light-weight [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
   interpreter written in Rust.
  - *Rigorous* - A rigorous enforcer of well-defined Rego semantics.

## Installation

Regorus can be used in Ruby by configuring bundler to build from the remote git source.

If using [Bundler](https://bundler.io/) to manage gems (recommended), edit your gemfile to include the following
`
gem "regorusrb", git: "https://github.com/microsoft/regorus/", glob: "bindings/ruby/*.gemspec"
`

or manually install checkout the source and build the gem

`
git clone https://github.com/microsoft/regorus/
cd regorus/bindings/ruby
rake && rake build # should eventually output 'regorusrb 0.1.0 built to pkg/regorusrb-0.1.0.gem.'
gem install --local ./pkg/regorusrb-0.1.0.gem
`

It is not yet available in rubygems.

See [Repository](https://github.com/microsoft/regorus).

To build this gem locally without bundler,

`rake build`

then to install the gem and build the native extensions

`gem install --local ./pkg/regorusrb-0.1.0.gem`

## Usage

```ruby
require "regorus"

engine = Regorus::Engine.new

# Policy is old-style.
engine.set_rego_v0(true)

engine.add_policy_from_file('../../tests/aci/framework.rego')
engine.add_policy_from_file('../../tests/aci/api.rego')
engine.add_policy_from_file('../../tests/aci/policy.rego')


# can be strings or symbols
data = {
  metadata: {
    devices: {
      "/run/layers/p0-layer0": "1b80f120dbd88e4355d6241b519c3e25290215c469516b49dece9cf07175a766",
      "/run/layers/p0-layer1": "e769d7487cc314d3ee748a4440805317c19262c7acd2fdbdb0d47d2e4613a15c",
      "/run/layers/p0-layer2": "eb36921e1f82af46dfe248ef8f1b3afb6a5230a64181d960d10237a08cd73c79",
      "/run/layers/p0-layer3": "41d64cdeb347bf236b4c13b7403b633ff11f1cf94dbc7cf881a44d6da88c5156",
      "/run/layers/p0-layer4": "4dedae42847c704da891a28c25d32201a1ae440bce2aecccfa8e6f03b97a6a6c",
      "/run/layers/p0-layer5": "fe84c9d5bfddd07a2624d00333cf13c1a9c941f3a261f13ead44fc6a93bc0e7a"
    }
  }
}

engine.add_data(data)
input = {
  "containerID": "container0",
  "layerPaths": [
    "/run/layers/p0-layer0",
    "/run/layers/p0-layer1",
    "/run/layers/p0-layer2",
    "/run/layers/p0-layer3",
    "/run/layers/p0-layer4",
    "/run/layers/p0-layer5"
  ],
  "target": "/run/gcs/c/container0/rootfs"
}

engine.set_input(input)

# Evaluate a specife rule
rule_results = engine.eval_rule('data.framework.mount_overlay')
puts rule_results # { "allowed" => true, "metadata" => [...]}

# Or evalute a full policy document
query_results = engine.eval_query('data.framework')
puts query_results[:result][0]

# Query results can can also be returned as JSON strings instead of Ruby Hash structure
results_json = engine.eval_query_as_json('data.framework.mount_overlay=x')
puts results_json
```

## Development

To update the gem version or dependencies within `bindings/ruby/Gemfile.lock`, run `bundle update --gemfile=bindings/ruby/Gemfile` from the project directory, or `cd bindings/ruby && bundle update`

After checking out the repo, `cd bindings/ruby` and run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.


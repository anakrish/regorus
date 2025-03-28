# frozen_string_literal: true

require "test_helper"
require "json"

class TestRegorus < Minitest::Test
  ALICE = "Alice"
  BOB = "Bob"
  CARLOS = "Carlos"

  def setup
    @engine = ::Regorus::Engine.new
    @engine.add_policy("regorus_test.rego", example_policy)
    @engine.add_data(example_data)
  end

  def example_policy
    <<~REGO
      package regorus_test
      is_manager if {
        input.name == data.managers[_]
      }

      is_employee if {
        input.name == data.employees[_]
      }

      # Set a default value for to return false instead of nil
      default is_manager_bool = false
      default is_employee_bool = false

      is_manager_bool if {
        is_manager
      }

      is_employee_bool if {
        is_employee
      }
    REGO
  end

  def example_data
    {
      "managers" => [ALICE],
      "employees" => [ALICE, BOB]
    }
  end

  def input_for(name)
    { "name" => name }
  end

  def test_version_number_presence
    refute_nil ::Regorus::VERSION
  end

  def test_engine_creation
    assert_instance_of ::Regorus::Engine, ::Regorus::Engine.new
  end

  def test_policy_addition
    # returns the package name from the REGO, not the filename
    assert_equal "data.regorus_test", @engine.add_policy("example.rego", example_policy)
  end

  def test_object_creation_with_new
    refute_same ::Regorus::Engine.new, ::Regorus::Engine.new
  end

  def test_data_addition
    assert_silent { @engine.add_data(example_data) }
  end

  def test_data_addition_as_json
    assert_silent { @engine.add_data_json(example_data.to_json) }
  end

  def test_query_evaluation_for_alice
    @engine.set_input(input_for(ALICE))

    assert_equal alice_results, @engine.eval_query("data.regorus_test")
  end

  def test_query_evaluation_for_bob
    @engine.set_input(input_for(BOB))

    assert_equal bob_results, @engine.eval_query("data.regorus_test")
  end

  def test_query_evaluation_as_json
    @engine.set_input(input_for(ALICE))

    assert_equal alice_results.to_json, @engine.eval_query_as_json("data.regorus_test")
  end

  def test_rule_evaluation_for_alice
    @engine.set_input(input_for(ALICE))

    assert @engine.eval_rule("data.regorus_test.is_employee")
    assert @engine.eval_rule("data.regorus_test.is_employee_bool")
    assert @engine.eval_rule("data.regorus_test.is_manager")
    assert @engine.eval_rule("data.regorus_test.is_manager_bool")
  end

  def test_rule_evaluation_for_bob
    @engine.set_input(input_for(BOB))

    assert @engine.eval_rule("data.regorus_test.is_employee")
    assert @engine.eval_rule("data.regorus_test.is_employee_bool")
    assert_nil @engine.eval_rule("data.regorus_test.is_manager")
    refute @engine.eval_rule("data.regorus_test.is_manager_bool")
  end

  def test_rule_evaluation_for_carlos
    @engine.set_input(input_for(CARLOS))

    assert_nil @engine.eval_rule("data.regorus_test.is_employee")
    refute @engine.eval_rule("data.regorus_test.is_employee_bool")
    assert_nil @engine.eval_rule("data.regorus_test.is_manager")
    refute @engine.eval_rule("data.regorus_test.is_manager_bool")
  end

  def test_eval_bool_query
    assert @engine.eval_bool_query("1 < 2")
    refute @engine.eval_bool_query("1 > 2")
    assert_raises(RuntimeError) { @engine.eval_bool_query("1 + 1") }
    assert_raises(RuntimeError) { @engine.eval_bool_query("true; true") }
    assert_raises(RuntimeError) { @engine.eval_bool_query("true; false; true") }
  end

  def test_eval_allow_query
    assert @engine.eval_allow_query("1 < 2")
    refute @engine.eval_allow_query("1 > 2")
    refute @engine.eval_allow_query("1 + 1")
    refute @engine.eval_allow_query("true; true")
    refute @engine.eval_allow_query("true; false; true")
  end

  def test_eval_deny_query
    assert @engine.eval_deny_query("1 < 2")
    refute @engine.eval_deny_query("1 > 2")
    assert @engine.eval_deny_query("1 + 1")
    assert @engine.eval_deny_query("true; true")
    assert @engine.eval_deny_query("true; false; true")
  end

  def test_missing_rules_handling
    @engine.set_input(input_for(ALICE))
    assert_raises(RuntimeError) { @engine.eval_rule("data.regorus_test.not_a_rule") }
  end

  def test_engine_cloning
    cloned_engine = @engine.clone

    assert_instance_of ::Regorus::Engine, cloned_engine
    refute_same @engine, cloned_engine
  end

  def test_coverage_printing_json
    @engine.set_input(input_for(ALICE))
    @engine.set_enable_coverage(true)
    @engine.eval_rule("data.regorus_test.is_employee")

    assert_match(/covered":\[7\],"not_covered":\[3,11,12,15,19\]/, @engine.get_coverage_report_as_json)
  end

  def test_coverage_printing_pretty
    @engine.set_input(input_for(ALICE))
    @engine.set_enable_coverage(true)
    @engine.eval_rule("data.regorus_test.is_employee")

    # to see the colors in the ruby terminal, use `puts @engine.get_coverage_report``
    pretty_coverage_report = @engine.get_coverage_report_pretty

    assert_match(/\e\[31m    3    input.name == data.managers\[_\]/, pretty_coverage_report)
    assert_match(/\e\[32m    7    input.name == data.employees\[_\]/, pretty_coverage_report)
  end

  def test_gather_print_statements
    @engine.set_gather_prints(true)
    @engine.eval_query('print("Hello")')

    assert_equal ["<query.rego>:1: Hello"], @engine.take_prints
  end

  def alice_results
    {
      result: [
        {
          expressions: [
            {
              value: {
                "is_employee" => true,
                "is_employee_bool" => true,
                "is_manager" => true,
                "is_manager_bool" => true
              },
              text: "data.regorus_test",
              location: {
                row: 1,
                col: 1
              }
            }
          ]
        }
      ]
    }
  end

  def bob_results
    {
      result: [
        {
          expressions: [
            {
              value: {
                "is_employee" => true,
                "is_employee_bool" => true,
                "is_manager_bool" => false
              },
              text: "data.regorus_test",
              location: {
                row: 1,
                col: 1
              }
            }
          ]
        }
      ]
    }
  end
end

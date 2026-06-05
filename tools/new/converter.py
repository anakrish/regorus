"""
Main RVM to SMT converter module.

This module provides the core conversion logic for translating Regorus RVM
bytecode programs into SMT-LIB format for formal verification.
"""

import sys
import os
from typing import Dict, List, Optional, Tuple, Callable, Any


class RVMRegister:
    """Represents an RVM register in Z3 modeling"""
    
    def __init__(self, rule_name: str, defn_idx: int, idx:int, name: Optional[str] = None):
        self.name = name or f"TMP_{rule_name}_{defn_idx}_{idx}"
        self.value_type = "RegoValue"
    
    def get_declarations(self) -> List[str]:
        """Get Z3 declarations for this register"""
        return [f"(declare-fun {self.name} () {self.value_type})"]
    
    def __str__(self):
        return self.name

class RvmToSmtConverter:
    """RVM to Z3 converter"""

    
    def __init__(self):
        self.program : Dict = {}

        # Components of SMT
        self.sort_declarations: List[str] = []
        
        
        # Current rule information
        self.current_rule_idx: int = -1
        self.current_rule_info: Dict = None
        self.current_defn_idx : int = -1
        self.current_body_idx : int = -1
        
    def _init_rego_sorts(self):
        """Initialize Rego value sorts for Z3"""
        self.sort_declarations.extend([
            "; Rego value types",
            "(declare-sort RegoValue 0)",
            "(declare-sort RegoObject 0)",
            "(declare-sort RegoArray 0)",
            "(declare-sort RegoSet 0)",
            "(declare-sort RegoString 0)",
            "(declare-sort RegoNumber 0)",
            "(declare-sort RegoBool 0)",
            "(declare-sort RegoNull 0)",
            "",
            "; Rego value constructors",
            "(declare-fun rego-null () RegoValue)",
            "(declare-fun rego-bool (Bool) RegoValue)",
            "(declare-fun rego-number (Real) RegoValue)",
            "(declare-fun rego-string (String) RegoValue)",
            "(declare-fun rego-array (RegoArray) RegoValue)",
            "(declare-fun rego-object (RegoObject) RegoValue)",
            "(declare-fun rego-set (RegoSet) RegoValue)",
            "",
        ])

    def _init_rego_functions(self):
        """Initialize Rego operation functions for Z3"""
        self.function_declarations.extend([
            "; Rego arithmetic operations",
            "(declare-fun rego-add (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-sub (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-mul (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-div (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-mod (RegoValue RegoValue) RegoValue)",
            "",
            "; Rego comparison operations",
            "(declare-fun rego-eq (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-ne (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-lt (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-le (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-gt (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-ge (RegoValue RegoValue) RegoValue)",
            "",
            "; Rego logical operations",
            "(declare-fun rego-and (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-or (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-not (RegoValue) RegoValue)",
            "",
            "; Rego collection operations",
            "(declare-fun rego-index (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-contains (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-count (RegoValue) RegoValue)",
            "",
            "; Rego object operations",
            "(declare-fun rego-object-get (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-object-set (RegoValue RegoValue RegoValue) RegoValue)",
            "",
            "; Rego array operations",
            "(declare-fun rego-array-get (RegoValue Int) RegoValue)",
            "(declare-fun rego-array-append (RegoValue RegoValue) RegoValue)",
            "",
            "; Rego set operations",
            "(declare-fun rego-set-add (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-set-union (RegoValue RegoValue) RegoValue)",
            "(declare-fun rego-set-intersection (RegoValue RegoValue) RegoValue)",
            "",
        ])
        
    def _value_to_smt(self, value: Any) -> str:
        """Convert a literal value to SMT representation"""
        if value is None:
            return "rego-null"
        elif isinstance(value, bool):
            return f"(rego-bool {'true' if value else 'false'})"
        elif isinstance(value, (int, float)):
            return f"(rego-number {value})"
        elif isinstance(value, str):
            return f'(rego-string "{value}")'
        elif isinstance(value, list):
            # Arrays need special handling
            return f"(rego-array {self._array_to_smt(value)})"
        elif isinstance(value, dict):
            # Objects need special handling
            return f"(rego-object {self._object_to_smt(value)})"
        else:
            return f"(rego-string \"{repr(value)}\")"

    def _array_to_smt(self, array: List[Any]) -> str:
        """Convert array to SMT representation"""
        # Simplified array representation
        return f"array_{len(array)}_elements"
    
    def _object_to_smt(self, obj: Dict[str, Any]) -> str:
        """Convert object to SMT representation"""
        # Simplified object representation
        return f"object_{len(obj)}_fields"
        
    def convert_program(self, program: Dict):
        self._initialize_conversion_state(program)
        self._convert_rules()

    def _initialize_conversion_state(self, program: Dict):
        """Initialize converter state for a new program"""
        self.program = program

        self.current_rule_id = -1
        self.current_defn_idx = -1
        self.current_body_idx = -1

        # Build rule boundaries cache
        self._dump_rule_boundaries()
        

    def _get_definition_boundary(self, rule_idx: int, defn_idx: int) -> Tuple[int,int]:
        rule_infos = self.program['rule_infos']
        rule_info = rule_infos[rule_idx]
        definitions = rule_info['definitions']
        if defn_idx < len(definitions) - 1:
            return (definitions[def_idx][0], definitions[def_idx + 1][0])
        else:
            # Last definition
            if rule_idx == len(rule_infos) -1:
                # Last rule
                return (definitions[defn_idx][0], len(self.program['instructions']))
            else:
                return (definitions[defn_idx][0], rule_infos[rule_idx+1]['definitions'][0][0])
            
            
    def _dump_rule_boundaries(self):
        """Build cache of rule boundaries for efficient processing"""
        rule_infos = self.program['rule_infos']
        for rule_idx, rule_info in enumerate(rule_infos):
            definitions = rule_info['definitions']
            for defn_idx in range(0, len(definitions)):
                print(f"Boundary for {rule_info['name']} definition {defn_idx}: ", end="")
                print(self._get_definition_boundary(rule_idx, defn_idx))
            
    def _convert_rules(self):
        rule_infos = self.program['rule_infos']
        for rule_idx, rule_info in enumerate(rule_infos):
            self._convert_rule(rule_idx, rule_info)

    def _convert_rule(self, rule_idx, rule_info):
        print(f"Converting rule {rule_info['name']}")
        self.current_rule_idx = rule_idx
        self.current_rule_info = rule_info
        for defn_idx in range(0, len(rule_info['definitions'])):
            self._convert_definition(defn_idx)

    def _convert_definition(self, defn_idx):
        print(f"Converting definition {defn_idx}")
        self.current_defn_idx = defn_idx
        definition = self.current_rule_info['definitions'][defn_idx]
        for body_idx, body_start_idx in enumerate(definition):
            self._convert_body(body_idx, body_start_idx)
                
    def _convert_body(self, body_idx, body_start_idx):
        print(f"Converting body {body_idx}", end="")
        self.current_body_idx = body_idx
        definitions = self.current_rule_info['definitions']
        if self.current_defn_idx < len(definitions) - 1:
            body_end_idx =  definitions[def_idx + 1]
        else:
            # Last definition
            rule_infos = self.program['rule_infos']
            if self.current_rule_idx == len(rule_infos) - 1:
                # Last rule
                body_end_idx = len(self.program['instructions'])
            else:
                body_end_idx = rule_infos[self.current_rule_idx + 1]['definitions'][0]
        print(f"at instructions[{body_start_idx}..{body_end_idx}]")
        instructions = self.program['instructions']
        pc = body_start_idx
        while pc < body_end_idx:
            inst = instructions[pc]
            self._convert_instruction(inst)
            pc += 1
            
    def _convert_instruction(self, inst):
        print(inst) 

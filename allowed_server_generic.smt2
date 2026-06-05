;; Generic SMT2 encoding of RVM program
;; Auto-generated from program JSON without hardcoding

(set-logic ALL)

;; Finite Domain Constants
(declare-const str_0 String)
(declare-const str_1 String)
(declare-const str_2 String)
(declare-const str_3 String)
(declare-const str_4 String)
(declare-const str_5 String)
(declare-const str_6 String)
(declare-const str_7 String)
(declare-const str_8 String)
(declare-const str_9 String)
(declare-const str_10 String)
(declare-const str_11 String)
(assert (= str_0 "id"))
(assert (= str_1 "public"))
(assert (= str_2 "networks"))
(assert (= str_3 "allow"))
(assert (= str_4 "violation"))
(assert (= str_5 "http"))
(assert (= str_6 "ports"))
(assert (= str_7 "<undefined>"))
(assert (= str_8 "protocols"))
(assert (= str_9 "network"))
(assert (= str_10 "telnet"))
(assert (= str_11 "servers"))
(assert (distinct str_0 str_1 str_2 str_3 str_4 str_5 str_6 str_7 str_8 str_9 str_10 str_11))
(declare-const int_0 Int)
(assert (= int_0 0))

;; Value Type System
(declare-sort RegValue 0)
(declare-sort RegArray 0)
(declare-sort RegObject 0)
(declare-sort RegSet 0)

;; Type predicates
(declare-fun is_string (RegValue) Bool)
(declare-fun is_int (RegValue) Bool)
(declare-fun is_bool (RegValue) Bool)
(declare-fun is_array (RegValue) Bool)
(declare-fun is_object (RegValue) Bool)
(declare-fun is_set (RegValue) Bool)
(declare-fun is_null (RegValue) Bool)

;; Value extractors
(declare-fun get_string (RegValue) String)
(declare-fun get_int (RegValue) Int)
(declare-fun get_bool (RegValue) Bool)

;; Value constructors
(declare-fun make_string (String) RegValue)
(declare-fun make_int (Int) RegValue)
(declare-fun make_bool (Bool) RegValue)
(declare-const null_value RegValue)
(declare-const undefined_value RegValue)

;; Constructor axioms
(assert (forall ((s String)) (is_string (make_string s))))
(assert (forall ((i Int)) (is_int (make_int i))))
(assert (forall ((b Bool)) (is_bool (make_bool b))))
(assert (is_null null_value))

;; Extractor axioms
(assert (forall ((s String)) (= (get_string (make_string s)) s)))
(assert (forall ((i Int)) (= (get_int (make_int i)) i)))
(assert (forall ((b Bool)) (= (get_bool (make_bool b)) b)))

;; Array operations
(declare-fun array_get (RegValue Int) RegValue)
(declare-fun array_length (RegValue) Int)
(declare-fun array_contains (RegValue RegValue) Bool)

;; Object operations
(declare-fun object_get (RegValue String) RegValue)
(declare-fun object_has_field (RegValue String) Bool)

;; Set operations
(declare-fun set_contains (RegValue RegValue) Bool)
(declare-fun set_add (RegValue RegValue) RegValue)
(declare-fun set_size (RegValue) Int)

;; Register Declarations
(declare-const data_example_allow_result RegValue)
(declare-const input RegValue)
(declare-const data_example_allow_def0_R2 RegValue)
(declare-const data_example_allow_def0_R3 RegValue)
(declare-const data_example_allow_def0_R4 RegValue)
(declare-const data_example_allow_def0_R5 RegValue)
(declare-const data_example_allow_def0_R6 RegValue)
(declare-const data_example_allow_def0_R7 RegValue)
(declare-const data_example_allow_def0_R9 RegValue)
(declare-const data_example_allow_def0_R10 RegValue)
(declare-const data_example_allow_def0_R11 RegValue)
(declare-const data_example_allow_def0_R12 RegValue)
(declare-const data_example_allow_def0_R13 RegValue)
(declare-const data_example_allow_def0_R15 RegValue)
(declare-const data_example_allow_def0_R16 RegValue)
(declare-const data_example_allow_def0_R17 RegValue)
(declare-const data_example_allow_def0_R21 RegValue)
(declare-const data_example_allow_def0_R22 RegValue)
(declare-const data_example_allow_def0_R23 RegValue)
(declare-const data_example_allow_def0_R24 RegValue)
(declare-const data_example_violation_result RegValue)
(declare-const data_example_violation_def0_R2 RegValue)
(declare-const data_example_violation_def0_R3 RegValue)
(declare-const data_example_violation_def0_R4 RegValue)
(declare-const data_example_violation_def0_R5 RegValue)
(declare-const data_example_violation_def0_R6 RegValue)
(declare-const data_example_violation_def0_R7 RegValue)
(declare-const data_example_violation_def0_R9 RegValue)
(declare-const data_example_violation_def0_R10 RegValue)
(declare-const data_example_violation_def0_R11 RegValue)
(declare-const data_example_violation_def0_R12 RegValue)
(declare-const data_example_violation_def0_R13 RegValue)
(declare-const data_example_violation_def0_R15 RegValue)
(declare-const data_example_violation_def0_R16 RegValue)
(declare-const data_example_violation_def0_R17 RegValue)
(declare-const data_example_violation_def0_R21 RegValue)
(declare-const data_example_violation_def0_R22 RegValue)
(declare-const data_example_violation_def0_R23 RegValue)
(declare-const data_example_violation_def0_R24 RegValue)
(declare-const data_example_violation_def1_R2 RegValue)
(declare-const data_example_violation_def1_R3 RegValue)
(declare-const data_example_violation_def1_R4 RegValue)
(declare-const data_example_violation_def1_R5 RegValue)
(declare-const data_example_violation_def1_R6 RegValue)
(declare-const data_example_violation_def1_R7 RegValue)
(declare-const data_example_violation_def1_R9 RegValue)
(declare-const data_example_violation_def1_R10 RegValue)
(declare-const data_example_violation_def1_R11 RegValue)
(declare-const data_example_violation_def1_R12 RegValue)
(declare-const data_example_violation_def1_R13 RegValue)
(declare-const data_example_violation_def1_R15 RegValue)
(declare-const data_example_violation_def1_R16 RegValue)
(declare-const data_example_violation_def1_R17 RegValue)
(declare-const data_example_violation_def1_R21 RegValue)
(declare-const data_example_violation_def1_R22 RegValue)
(declare-const data_example_violation_def1_R23 RegValue)
(declare-const data_example_violation_def1_R24 RegValue)
(declare-const data_example_public_server_result RegValue)
(declare-const data_example_public_server_def0_R2 RegValue)
(declare-const data_example_public_server_def0_R3 RegValue)
(declare-const data_example_public_server_def0_R4 RegValue)
(declare-const data_example_public_server_def0_R5 RegValue)
(declare-const data_example_public_server_def0_R6 RegValue)
(declare-const data_example_public_server_def0_R7 RegValue)
(declare-const data_example_public_server_def0_R9 RegValue)
(declare-const data_example_public_server_def0_R10 RegValue)
(declare-const data_example_public_server_def0_R11 RegValue)
(declare-const data_example_public_server_def0_R12 RegValue)
(declare-const data_example_public_server_def0_R13 RegValue)
(declare-const data_example_public_server_def0_R15 RegValue)
(declare-const data_example_public_server_def0_R16 RegValue)
(declare-const data_example_public_server_def0_R17 RegValue)
(declare-const data_example_public_server_def0_R21 RegValue)
(declare-const data_example_public_server_def0_R22 RegValue)
(declare-const data_example_public_server_def0_R23 RegValue)
(declare-const data_example_public_server_def0_R24 RegValue)

;; Input Structure from Schema Analysis
(declare-const input RegValue)
(assert (is_object input))
;; Comprehensive Schema-Based Constraints
;; Field path: servers
(declare-const input_servers RegValue)
(assert (= input_servers (object_get input "servers")))
(assert (is_array input_servers))
(assert (>= (array_length input_servers) 1))

;; Field path: servers.[]
(declare-const input_servers_item RegValue)
(assert (= input_servers_item (object_get input "servers")))
(assert (is_object input_servers_item))

;; Field path: servers.[].id
(declare-const input_servers_item_id RegValue)
(assert (= input_servers_item_id (object_get (object_get input "servers") "id")))
(assert (is_string input_servers_item_id))
;; String min length 1 (approximated)

;; Field path: servers.[].protocols
(declare-const input_servers_item_protocols RegValue)
(assert (= input_servers_item_protocols (object_get (object_get input "servers") "protocols")))
(assert (is_array input_servers_item_protocols))
(assert (>= (array_length input_servers_item_protocols) 1))
;; Array unique items constraint for input_servers_item_protocols (simplified)

;; Field path: servers.[].protocols.[]
(declare-const input_servers_item_protocols_item RegValue)
(assert (= input_servers_item_protocols_item (object_get (object_get input "servers") "protocols")))
(assert (is_string input_servers_item_protocols_item))
(assert (or (= input_servers_item_protocols_item (make_string str_5)) (= input_servers_item_protocols_item (make_string str_10))))

;; Field path: servers.[].ports
(declare-const input_servers_item_ports RegValue)
(assert (= input_servers_item_ports (object_get (object_get input "servers") "ports")))
(assert (is_array input_servers_item_ports))
(assert (>= (array_length input_servers_item_ports) 1))
;; Array unique items constraint for input_servers_item_ports (simplified)

;; Field path: servers.[].ports.[]
(declare-const input_servers_item_ports_item RegValue)
(assert (= input_servers_item_ports_item (object_get (object_get input "servers") "ports")))
(assert (is_string input_servers_item_ports_item))
;; String min length 1 (approximated)

;; Field path: networks
(declare-const input_networks RegValue)
(assert (= input_networks (object_get input "networks")))
(assert (is_array input_networks))
(assert (>= (array_length input_networks) 1))

;; Field path: networks.[]
(declare-const input_networks_item RegValue)
(assert (= input_networks_item (object_get input "networks")))
(assert (is_object input_networks_item))

;; Field path: networks.[].id
(declare-const input_networks_item_id RegValue)
(assert (= input_networks_item_id (object_get (object_get input "networks") "id")))
(assert (is_string input_networks_item_id))
;; String min length 1 (approximated)

;; Field path: networks.[].public
(declare-const input_networks_item_public RegValue)
(assert (= input_networks_item_public (object_get (object_get input "networks") "public")))
(assert (is_bool input_networks_item_public))

;; Field path: ports
(declare-const input_ports RegValue)
(assert (= input_ports (object_get input "ports")))
(assert (is_array input_ports))
(assert (>= (array_length input_ports) 1))

;; Field path: ports.[]
(declare-const input_ports_item RegValue)
(assert (= input_ports_item (object_get input "ports")))
(assert (is_object input_ports_item))

;; Field path: ports.[].id
(declare-const input_ports_item_id RegValue)
(assert (= input_ports_item_id (object_get (object_get input "ports") "id")))
(assert (is_string input_ports_item_id))
;; String min length 1 (approximated)

;; Field path: ports.[].network
(declare-const input_ports_item_network RegValue)
(assert (= input_ports_item_network (object_get (object_get input "ports") "network")))
(assert (is_string input_ports_item_network))
;; String min length 1 (approximated)


;; Converting rule data.example.allow
;; Converting definition 0
;; Converting body 0 at instructions[2..12]
;; Instruction 2: RuleInit
;; Rule init
;; Instruction 3: CallRule
;; Instruction 4: BuiltinCall
;; Builtin call: unknown
;; Instruction 5: Load
(assert (= data_example_allow_def0_R4 (make_int int_0)))
;; Instruction 6: Eq
(assert (is_bool data_example_allow_def0_R5))
(assert (= (get_bool data_example_allow_def0_R5)
  (ite (and (is_string data_example_allow_def0_R3) (is_string data_example_allow_def0_R4))
       (= (get_string data_example_allow_def0_R3) (get_string data_example_allow_def0_R4))
       (ite (and (is_int data_example_allow_def0_R3) (is_int data_example_allow_def0_R4))
            (= (get_int data_example_allow_def0_R3) (get_int data_example_allow_def0_R4))
            (ite (and (is_bool data_example_allow_def0_R3) (is_bool data_example_allow_def0_R4))
                 (= (get_bool data_example_allow_def0_R3) (get_bool data_example_allow_def0_R4))
                 false)))))
;; Instruction 7: CallRule
;; Instruction 8: ObjectCreate
(assert (is_object input))
(assert (= (object_get input "allow") data_example_allow_def0_R5))
(assert (= (object_get input "violation") data_example_allow_def0_R6))
;; Instruction 9: Move
(assert (= data_example_allow_def0_R7 input))
;; Instruction 10: Move
(assert (= data_example_allow_result data_example_allow_def0_R7))
;; Instruction 11: RuleReturn
;; Rule return
;; Converting rule data.example.violation
;; Converting definition 0
;; Converting body 0 at instructions[12..26]
;; Instruction 12: RuleInit
;; Rule init
;; Instruction 13: CallRule
;; Instruction 14: LoopStart
;; Loop start - collection: 1, mode: ForEach
;; Instruction 15: AssertCondition
(assert (is_bool data_example_violation_def0_R3))
(assert (get_bool data_example_violation_def0_R3))
;; Instruction 16: IndexLiteral
(assert (= data_example_violation_def0_R5 (object_get data_example_violation_def0_R2 "protocols")))
;; Instruction 17: LoopStart
;; Loop start - collection: 5, mode: ForEach
;; Instruction 18: Load
(assert (= data_example_violation_def0_R9 (make_string str_5)))
;; Instruction 19: Eq
(assert (is_bool data_example_violation_def0_R10))
(assert (= (get_bool data_example_violation_def0_R10)
  (ite (and (is_string data_example_violation_def0_R7) (is_string data_example_violation_def0_R9))
       (= (get_string data_example_violation_def0_R7) (get_string data_example_violation_def0_R9))
       (ite (and (is_int data_example_violation_def0_R7) (is_int data_example_violation_def0_R9))
            (= (get_int data_example_violation_def0_R7) (get_int data_example_violation_def0_R9))
            (ite (and (is_bool data_example_violation_def0_R7) (is_bool data_example_violation_def0_R9))
                 (= (get_bool data_example_violation_def0_R7) (get_bool data_example_violation_def0_R9))
                 false)))))
;; Instruction 20: AssertCondition
(assert (is_bool data_example_violation_def0_R10))
(assert (get_bool data_example_violation_def0_R10))
;; Instruction 21: IndexLiteral
(assert (= data_example_violation_def0_R11 (object_get data_example_violation_def0_R2 "id")))
;; Instruction 22: SetAdd
(assert (set_contains data_example_violation_result data_example_violation_def0_R11))
;; Instruction 23: LoopNext
;; Loop next - body_start: 18, loop_end: 24
;; Instruction 24: LoopNext
;; Loop next - body_start: 15, loop_end: 25
;; Instruction 25: RuleReturn
;; Rule return
;; Converting definition 1
;; Converting body 0 at instructions[26..41]
;; Instruction 26: RuleInit
;; Rule init
;; Instruction 27: LoadInput
(assert (= input input))
;; Instruction 28: IndexLiteral
(assert (= data_example_violation_def1_R2 (object_get input "servers")))
;; Instruction 29: LoopStart
;; Loop start - collection: 2, mode: ForEach
;; Instruction 30: Move
(assert (= data_example_violation_def1_R6 data_example_violation_def1_R4))
;; Instruction 31: IndexLiteral
(assert (= data_example_violation_def1_R7 (object_get data_example_violation_def1_R6 "protocols")))
;; Instruction 32: LoopStart
;; Loop start - collection: 7, mode: ForEach
;; Instruction 33: Load
(assert (= data_example_violation_def1_R11 (make_string str_10)))
;; Instruction 34: Eq
(assert (is_bool data_example_violation_def1_R12))
(assert (= (get_bool data_example_violation_def1_R12)
  (ite (and (is_string data_example_violation_def1_R9) (is_string data_example_violation_def1_R11))
       (= (get_string data_example_violation_def1_R9) (get_string data_example_violation_def1_R11))
       (ite (and (is_int data_example_violation_def1_R9) (is_int data_example_violation_def1_R11))
            (= (get_int data_example_violation_def1_R9) (get_int data_example_violation_def1_R11))
            (ite (and (is_bool data_example_violation_def1_R9) (is_bool data_example_violation_def1_R11))
                 (= (get_bool data_example_violation_def1_R9) (get_bool data_example_violation_def1_R11))
                 false)))))
;; Instruction 35: AssertCondition
(assert (is_bool data_example_violation_def1_R12))
(assert (get_bool data_example_violation_def1_R12))
;; Instruction 36: IndexLiteral
(assert (= data_example_violation_def1_R13 (object_get data_example_violation_def1_R6 "id")))
;; Instruction 37: SetAdd
(assert (set_contains data_example_violation_result data_example_violation_def1_R13))
;; Instruction 38: LoopNext
;; Loop next - body_start: 33, loop_end: 39
;; Instruction 39: LoopNext
;; Loop next - body_start: 30, loop_end: 40
;; Instruction 40: RuleReturn
;; Rule return
;; Converting rule data.example.public_server
;; Converting definition 0
;; Converting body 0 at instructions[41..67]
;; Instruction 41: RuleInit
;; Rule init
;; Instruction 42: LoadInput
(assert (= input input))
;; Instruction 43: IndexLiteral
(assert (= data_example_public_server_def0_R2 (object_get input "servers")))
;; Instruction 44: LoopStart
;; Loop start - collection: 2, mode: ForEach
;; Instruction 45: Move
(assert (= data_example_public_server_def0_R6 data_example_public_server_def0_R4))
;; Instruction 46: IndexLiteral
(assert (= data_example_public_server_def0_R7 (object_get data_example_public_server_def0_R6 "ports")))
;; Instruction 47: LoopStart
;; Loop start - collection: 7, mode: ForEach
;; Instruction 48: IndexLiteral
(assert (= data_example_public_server_def0_R11 (object_get input "ports")))
;; Instruction 49: LoopStart
;; Loop start - collection: 11, mode: ForEach
;; Instruction 50: ChainedIndex
(assert (= data_example_public_server_def0_R15 (object_get (array_get (object_get input "ports") (get_int data_example_public_server_def0_R12)) "id")))
;; Instruction 51: Eq
(assert (is_bool data_example_public_server_def0_R16))
(assert (= (get_bool data_example_public_server_def0_R16)
  (ite (and (is_string data_example_public_server_def0_R9) (is_string data_example_public_server_def0_R15))
       (= (get_string data_example_public_server_def0_R9) (get_string data_example_public_server_def0_R15))
       (ite (and (is_int data_example_public_server_def0_R9) (is_int data_example_public_server_def0_R15))
            (= (get_int data_example_public_server_def0_R9) (get_int data_example_public_server_def0_R15))
            (ite (and (is_bool data_example_public_server_def0_R9) (is_bool data_example_public_server_def0_R15))
                 (= (get_bool data_example_public_server_def0_R9) (get_bool data_example_public_server_def0_R15))
                 false)))))
;; Instruction 52: AssertCondition
(assert (is_bool data_example_public_server_def0_R16))
(assert (get_bool data_example_public_server_def0_R16))
;; Instruction 53: IndexLiteral
(assert (= data_example_public_server_def0_R17 (object_get input "networks")))
;; Instruction 54: LoopStart
;; Loop start - collection: 17, mode: ForEach
;; Instruction 55: ChainedIndex
(assert (= data_example_public_server_def0_R21 (object_get (array_get (object_get input "ports") (get_int data_example_public_server_def0_R12)) "network")))
;; Instruction 56: ChainedIndex
(assert (= data_example_public_server_def0_R22 (object_get (array_get (object_get input "networks") (get_int data_example_public_server_def0_R18)) "id")))
;; Instruction 57: Eq
(assert (is_bool data_example_public_server_def0_R23))
(assert (= (get_bool data_example_public_server_def0_R23)
  (ite (and (is_string data_example_public_server_def0_R21) (is_string data_example_public_server_def0_R22))
       (= (get_string data_example_public_server_def0_R21) (get_string data_example_public_server_def0_R22))
       (ite (and (is_int data_example_public_server_def0_R21) (is_int data_example_public_server_def0_R22))
            (= (get_int data_example_public_server_def0_R21) (get_int data_example_public_server_def0_R22))
            (ite (and (is_bool data_example_public_server_def0_R21) (is_bool data_example_public_server_def0_R22))
                 (= (get_bool data_example_public_server_def0_R21) (get_bool data_example_public_server_def0_R22))
                 false)))))
;; Instruction 58: AssertCondition
(assert (is_bool data_example_public_server_def0_R23))
(assert (get_bool data_example_public_server_def0_R23))
;; Instruction 59: ChainedIndex
(assert (= data_example_public_server_def0_R24 (object_get (array_get (object_get input "networks") (get_int data_example_public_server_def0_R18)) "public")))
;; Instruction 60: AssertCondition
(assert (is_bool data_example_public_server_def0_R24))
(assert (get_bool data_example_public_server_def0_R24))
;; Instruction 61: SetAdd
(assert (set_contains data_example_public_server_result data_example_public_server_def0_R6))
;; Instruction 62: LoopNext
;; Loop next - body_start: 55, loop_end: 63
;; Instruction 63: LoopNext
;; Loop next - body_start: 50, loop_end: 64
;; Instruction 64: LoopNext
;; Loop next - body_start: 48, loop_end: 65
;; Instruction 65: LoopNext
;; Loop next - body_start: 45, loop_end: 66
;; Instruction 66: RuleReturn
;; Rule return
;; Test Case Generation Constraints
(assert (or (= input_id (make_string str_0)) (= input_id (make_string str_1)) (= input_id (make_string str_2)) (= input_id (make_string str_3)) (= input_id (make_string str_4)) (= input_id (make_string str_5)) (= input_id (make_string str_6)) (= input_id (make_string str_7)) (= input_id (make_string str_8)) (= input_id (make_string str_9)) (= input_id (make_string str_10)) (= input_id (make_string str_11)) (= input_id (make_int int_0)) (= input_id (make_bool true)) (= input_id (make_bool false))))
(assert (or (= input_network (make_string str_0)) (= input_network (make_string str_1)) (= input_network (make_string str_2)) (= input_network (make_string str_3)) (= input_network (make_string str_4)) (= input_network (make_string str_5)) (= input_network (make_string str_6)) (= input_network (make_string str_7)) (= input_network (make_string str_8)) (= input_network (make_string str_9)) (= input_network (make_string str_10)) (= input_network (make_string str_11)) (= input_network (make_int int_0)) (= input_network (make_bool true)) (= input_network (make_bool false))))
(assert (>= (array_length input_networks) 1))
(assert (<= (array_length input_networks) 5))
(assert (forall ((i Int))
  (=> (and (>= i 0) (< i (array_length input_networks)))
      (is_object (array_get input_networks i)))))
(assert (>= (array_length input_ports) 1))
(assert (<= (array_length input_ports) 5))
(assert (forall ((i Int))
  (=> (and (>= i 0) (< i (array_length input_ports)))
      (is_object (array_get input_ports i)))))
(assert (or (= input_protocols (make_string str_0)) (= input_protocols (make_string str_1)) (= input_protocols (make_string str_2)) (= input_protocols (make_string str_3)) (= input_protocols (make_string str_4)) (= input_protocols (make_string str_5)) (= input_protocols (make_string str_6)) (= input_protocols (make_string str_7)) (= input_protocols (make_string str_8)) (= input_protocols (make_string str_9)) (= input_protocols (make_string str_10)) (= input_protocols (make_string str_11)) (= input_protocols (make_int int_0)) (= input_protocols (make_bool true)) (= input_protocols (make_bool false))))
(assert (or (= input_public (make_string str_0)) (= input_public (make_string str_1)) (= input_public (make_string str_2)) (= input_public (make_string str_3)) (= input_public (make_string str_4)) (= input_public (make_string str_5)) (= input_public (make_string str_6)) (= input_public (make_string str_7)) (= input_public (make_string str_8)) (= input_public (make_string str_9)) (= input_public (make_string str_10)) (= input_public (make_string str_11)) (= input_public (make_int int_0)) (= input_public (make_bool true)) (= input_public (make_bool false))))
(assert (or (= input_servers (make_string str_0)) (= input_servers (make_string str_1)) (= input_servers (make_string str_2)) (= input_servers (make_string str_3)) (= input_servers (make_string str_4)) (= input_servers (make_string str_5)) (= input_servers (make_string str_6)) (= input_servers (make_string str_7)) (= input_servers (make_string str_8)) (= input_servers (make_string str_9)) (= input_servers (make_string str_10)) (= input_servers (make_string str_11)) (= input_servers (make_int int_0)) (= input_servers (make_bool true)) (= input_servers (make_bool false))))

;; Generate test cases that violate the policy
;; Look for cases where the policy should fail

;; For allow policies, find inputs where allow should be false
;; Check rule results (register 0 in each rule's window)
;; (Additional constraints can be added here)

(check-sat)
(get-model)
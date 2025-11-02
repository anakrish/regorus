; RVM Assembly - 22 instructions, 6 literals, 0 builtins
;
; LITERALS (JSON values):
;   L 0: "alice"
;   L 1: "blue"
;   L 2: false
;   L 3: "user"
;   L 4: "team"
;   L 5: "approved"
;
; RULES TABLE:
;   R 0: data.example.allow
;
000: CallRule     r1 ← data.example.allow             ; Call rule 'data.example.allow' (R0) with caching
001: Return       return r1                             ; Return value from r1
; ===== RULE: data.example.allow =====
002: RuleInit     data.example.allow → r0 {           ; Initialize rule 'data.example.allow' (R0) evaluation
003:     LoadInput    r1 ← input                      ; Load global input document
004:     IndexLiteral r2 ← r1[L3]                     ; Index with literal key: r1["user"]
005:     Load         r3 ← L0                         ; Load literal: "alice"
006:     Eq           r4 ← (r2 = r3)                  ; Equality test: r2 == r3
007:     Assert       assert r4                         ; Assert r4 is true (exit if false/undefined)
008:     LoadBool     r5 ← true                       ; Load boolean constant true
009:     Move         r0 ← r5                         ; Copy value from r5 to r0
010: } return from rule                                 ; End of rule evaluation

; ===== RULE: data.example.allow =====
011: RuleInit     data.example.allow → r0 {           ; Initialize rule 'data.example.allow' (R0) evaluation
012:     LoadInput    r1 ← input                      ; Load global input document
013:     IndexLiteral r2 ← r1[L4]                     ; Index with literal key: r1["team"]
014:     Load         r3 ← L1                         ; Load literal: "blue"
015:     Eq           r4 ← (r2 = r3)                  ; Equality test: r2 == r3
016:     Assert       assert r4                         ; Assert r4 is true (exit if false/undefined)
017:     IndexLiteral r5 ← r1[L5]                     ; Index with literal key: r1["approved"]
018:     Assert       assert r5                         ; Assert r5 is true (exit if false/undefined)
019:     LoadBool     r6 ← true                       ; Load boolean constant true
020:     Move         r0 ← r6                         ; Copy value from r6 to r0
021: } return from rule                                 ; End of rule evaluation

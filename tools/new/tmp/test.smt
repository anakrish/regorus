(set-info :source |Regorus RVM Bytecode|)
(set-info :category "industrial")
(set-logic ALL)

(declare-sort RegoValue 0)
(declare-sort RegoObject 0)
(declare-sort RegoArray 0)
(declare-sort RegoSet 0)
(declare-sort RegoString 0)
(declare-sort RegoNumber 0)
(declare-sort RegoBool 0)
(declare-sort RegoNull 0)

; Rego value constructors,
(declare-fun rego-null () RegoValue)
(declare-fun rego-bool (Bool) RegoValue)
(declare-fun rego-number (Real) RegoValue)
(declare-fun rego-string (String) RegoValue)
(declare-fun rego-array (RegoArray) RegoValue)
(declare-fun rego-object (RegoObject) RegoValue)
(declare-fun rego-set (RegoSet) RegoValue)

; Rego arithmetic operations,
(declare-fun rego-add (RegoValue RegoValue) RegoValue)
(declare-fun rego-sub (RegoValue RegoValue) RegoValue)
(declare-fun rego-mul (RegoValue RegoValue) RegoValue)
(declare-fun rego-div (RegoValue RegoValue) RegoValue)
(declare-fun rego-mod (RegoValue RegoValue) RegoValue)

; Rego comparison operations,
(declare-fun rego-eq (RegoValue RegoValue) RegoValue)
(declare-fun rego-ne (RegoValue RegoValue) RegoValue)
(declare-fun rego-lt (RegoValue RegoValue) RegoValue)
(declare-fun rego-le (RegoValue RegoValue) RegoValue)
(declare-fun rego-gt (RegoValue RegoValue) RegoValue)
(declare-fun rego-ge (RegoValue RegoValue) RegoValue)

; Rego logical operations,
(declare-fun rego-and (RegoValue RegoValue) RegoValue)
(declare-fun rego-or (RegoValue RegoValue) RegoValue)
(declare-fun rego-not (RegoValue) RegoValue)

; Rego collection operations,
(declare-fun rego-index (RegoValue RegoValue) RegoValue)
(declare-fun rego-contains (RegoValue RegoValue) RegoValue)
(declare-fun rego-count (RegoValue) RegoValue)

; Rego object operations
(declare-fun rego-object-get (RegoValue RegoValue) RegoValue)
(declare-fun rego-object-set (RegoValue RegoValue RegoValue) RegoValue)

; Rego array operations,
(declare-fun rego-array-get (RegoValue Int) RegoValue)
(declare-fun rego-array-append (RegoValue RegoValue) RegoValue)

; Rego set operations,
(declare-fun rego-set-add (RegoValue RegoValue) RegoValue)
(declare-fun rego-set-union (RegoValue RegoValue) RegoValue)
(declare-fun rego-set-intersection (RegoValue RegoValue) RegoValue)

(declare-fun x () RegoValue)

(assert (= x (rego-number 5) (rego-number 6)))

(check-sat)
(get-model)
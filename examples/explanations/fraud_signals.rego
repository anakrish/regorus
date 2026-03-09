package demo
import rego.v1

alerts contains msg if {
    txn := input.transactions[_]
    startswith(lower(txn.merchant), "gift")
    txn.amount >= 500
    txn.country != input.account.home_country
    not txn.card_present
    msg := sprintf("transaction %v looks like gift-card laundering", [txn.id])
}

alerts contains msg if {
    txn := input.transactions[_]
    endswith(lower(txn.merchant), ".ru")
    txn.amount > 100
    msg := sprintf("transaction %v targets suspicious merchant domain", [txn.id])
}

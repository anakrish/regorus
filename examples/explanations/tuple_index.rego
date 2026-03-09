package demo
import rego.v1

violations contains msg if {
    t := [input.x, input.y]
    t[0] == 5
    msg := "The first tuple element is 5"
}

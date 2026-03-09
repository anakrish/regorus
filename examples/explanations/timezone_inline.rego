package demo
import rego.v1

violations contains msg if {
    clock_timezone := data.config.DEVICE_METADATA.localhost
    clock_timezone.timezone != "UTC"
    msg := "The clock timezone is not set to UTC"
}

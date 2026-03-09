package demo
import rego.v1

check_clock_time_zone if {
    clock_timezone := data.config.DEVICE_METADATA.localhost
    clock_timezone.timezone != "UTC"
}

violations contains msg if {
    check_clock_time_zone
    msg := "The clock timezone is not set to UTC"
}
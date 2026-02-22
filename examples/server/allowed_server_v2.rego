package example

# v2: Maximally restructured — same HTTP→public semantics; telnet rule dropped.
#
# Structural differences from v1:
#   1. `not` + boolean helper     replaces   violation partial-set + count==0
#   2. Set comprehension          replaces   `public_server` helper rule
#   3. Function rules             replaces   inline joins
#   4. `proto == "http"`          replaces   `"http" in server.protocols`
#   5. `some i, val in` iteration replaces   `some val in` + member test
#   6. `allow if`                 replaces   `allow := true if`
#   7. Totally different decomp   replaces   v1's 3-rule structure

default allow := false

allow if {
    not http_on_public_network
}

# Comprehension: set of port IDs that sit on a public network
public_port_ids := {port.id |
    some port in input.ports
    is_public_network(port.network)
}

# Function: is a given network ID public?
is_public_network(net_id) if {
    some network in input.networks
    network.id == net_id
    network.public == true
}

# Function: does a server have at least one port on a public network?
server_is_public(server) if {
    some port_ref in server.ports
    port_ref in public_port_ids
}

# Function: does a server speak HTTP?
speaks_http(server) if {
    some proto in server.protocols
    proto == "http"
}

# Main check: any server that speaks HTTP and is publicly reachable
http_on_public_network if {
    some server in input.servers
    speaks_http(server)
    server_is_public(server)
}

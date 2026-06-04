package ex

v := [1, 2, 3]

r := 5 if {
	every val in v {
		val > 3
	}
}

allowed_repos := {"hooli.com/", "acmecorp.net/"}
containers := [
	{"image": "hooli.com/bitcoin-miner"},
	{"image": "acmecorp.net/webapp"},
	#{"image": "nginx"}
]

p if {
	every c in containers {
		some repo in allowed_repos
		startswith(c.image, repo)
	}
}
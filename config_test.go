package secbot

import "strings"

func ExampleGetHandlerConfig() {
	GetHandlerConfig("s3", "default_account")
	// Output: "prod", nil
}

func ExampleSetHandlerConfig() {
	SetHandlerConfig("s3", "default_account", "prod")
}

func ExampleGetTrackedUsers() {
	GetTrackedUsers("slack", "pagarme", "nomfa")
	// Output: []string{"john", "mary"}, nil
}

func ExampleTrackUser() {
	TrackUser("slack", "pagarme", "member", "john", "INSERT")

	TrackUser("slack", "pagarme", "member", "richard", "DELETE")
}

func ExampleListTrackedData() {
	ListTrackedData("readmeio", "pagarme")
	// Output: "page1234", nil
}

func ExampleGetTrackedData() {
	GetTrackedData("readmeio", "pagarme", "page1234")
	// Output: "change1 change2 change3", nil
}

func ExampleTrackData() {
	var slug_changes []string

	slug_changes = append(slug_changes, "change1")
	slug_changes = append(slug_changes, "change2")
	slug_changes = append(slug_changes, "change3")

	TrackData("readmeio", "pagarme", "page1234", strings.Join(slug_changes, " "), "INSERT")

	var deleted_slugs []string

	deleted_slugs = append(deleted_slugs, "change4")

	TrackData("readmeio", "pagarme", "page1234", strings.Join(deleted_slugs, " "), "DELETE")
}

func ExampleGetHome() {
	GetHome()
	//Output: "/home/secbot"
}

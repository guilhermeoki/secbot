package secbot

func ExampleAtBot_false() {
	AtBot("@john you can use @secbot auth list to list the registered permissions")
	// Output: false
}

func ExampleAtBot_true() {
	AtBot("@secbot auth list") // @secbot raw value is <@U12345>, with U12345 being the same as the botId global variable
	// Output: true
}

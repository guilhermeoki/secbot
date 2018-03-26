package secbot

func ExampleCredentialsListCredentials() {
	CredentialsListCredentials("github")
	// Output: []ExternalCredential{ExternalCredential{Module: "github", Name: "pagarme", Login: "pagarme", Password: "ohsosecret"}}, nil
}

func ExampleCredentialsGetCredential() {
	CredentialsGetCredential("github", "pagarme")
	// Output: ExternalCredential{Module: "github", Name: "pagarme", Login: "pagarme", Password: "ohsosecret"}, nil
}

func ExampleCredentialsSetCredential() {
	var ex ExternalCredential

	ex.Module = "github"
	ex.Name = "pagarme"

	ex.Login = "pagarme"
	ex.Password = "ohsosecret"

	CredentialsSetCredential(ex)
}

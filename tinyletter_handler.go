package secbot

import (
	"fmt"
	tiny "github.com/kamushadenes/tinygo/api"
	"github.com/levigross/grequests"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
	"time"
)

func TinyLetterHandlerStart() {

	RegisterHandler("tinyletter")

	AddCommand(Command{
		Regex:       regexp.MustCompile("tinyletter (?P<command>list accounts)"),
		Help:        "Obtém a lista de contas cadastradas",
		Usage:       "tinyletter list accounts",
		Handler:     TinyLetterListAccountsCommand,
		HandlerName: "tinyletter"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("tinyletter (?P<command>list subscribers)"),
		Help:        "Obtém lista de inscritos da conta",
		Usage:       "tinyletter list subscribers",
		Handler:     TinyLetterListSubscribersCommand,
		HandlerName: "tinyletter"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("tinyletter (?P<command>list subscribers) (?P<account>\\S+)"),
		Help:        "Obtém lista de inscritos da conta <account>",
		Usage:       "tinyletter list subscribers <account>",
		Handler:     TinyLetterListSubscribersCommand,
		HandlerName: "tinyletter",
		Parameters: map[string]string{
			"account": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("tinyletter (?P<command>set default account) (?P<account>\\S+)"),
		Help:               "Define a conta padrão do TinyLetter",
		Usage:              "tinyletter set default account <account>",
		Handler:            TinyLetterSetDefaultAccountCommand,
		HandlerName:        "tinyletter",
		RequiredPermission: "tinyletter",
		Parameters: map[string]string{
			"account": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("tinyletter (?P<command>set account) (?P<account>\\S+) (?P<login>\\S+) (?P<password>\\S+)"),
		Help:               "Seta a conta <account> com os dados informados",
		Usage:              "tinyletter set account <account> <login> <password>",
		Handler:            TinyLetterSetAccountCommand,
		HandlerName:        "tinyletter",
		RequiredPermission: "tinyletter",
		Parameters: map[string]string{
			"account":  "\\S+",
			"login":    "\\S+",
			"password": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("tinyletter (?P<command>set account) (?P<account>\\S+) (?P<login>\\S+) (?P<password>\\S+) (?P<domains>.*)"),
		Help:               "Seta a conta <account> com os dados informados",
		Usage:              "tinyletter set account <account> <login> <password> <domains>",
		Handler:            TinyLetterSetAccountCommand,
		HandlerName:        "tinyletter",
		RequiredPermission: "tinyletter",
		Parameters: map[string]string{
			"account":  "\\S+",
			"login":    "\\S+",
			"password": "\\S+",
			"domains":  ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("tinyletter (?P<command>set allowed domains) (?P<account>\\S+) (?P<domains>.*)"),
		Help:               "Seta os domínios permitidos para os inscritos da conta <account>",
		Usage:              "tinyletter set allowed domains <account> <domains>",
		Handler:            TinyLetterSetAllowedDomainsCommand,
		HandlerName:        "tinyletter",
		RequiredPermission: "tinyletter",
		Parameters: map[string]string{
			"account": "\\S+",
			"domains": ".*",
		}})

	go TinyLetterMonitorChanges()
}

func TinyLetterGetDefaultAccount() string {

	account, _ := GetHandlerConfig("tinyletter", "default_account")

	if len(account) == 0 {
		return ""
	}

	return account

}

/*
Creates a TinyLetter account.

HandlerName

 tinyletter

RequiredPermission

 tinyletter

Regex

 tinyletter (?P<command>set account) (?P<account>\\S+) (?P<login>\\S+) (?P<password>\\S+)

 tinyletter (?P<command>set account) (?P<account>\\S+) (?P<login>\\S+) (?P<password>\\S+) (?P<domains>.*)

Usage

 tinyletter set account <account> <login> <password>

 tinyletter set account <account> <login> <password> <domains>
*/
func TinyLetterSetAccountCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	var ex ExternalCredential

	ex.Module = "tinyletter"
	ex.Name = md["account"]

	if _, ok := md["token"]; ok {
		ex.Login = md["token"]
	} else {
		ex.Login = StripMailTo(md["login"])
		ex.Password = md["password"]
	}

	err := CredentialsSetCredential(ex)

	if _, ok := md["domains"]; ok {

		var domains []string

		for _, d := range strings.Split(md["domains"], " ") {
			domains = append(domains, StripURL(d))
		}

		SetHandlerConfig("tinyletter", fmt.Sprintf("allowed_domains_%s", md["account"]), strings.Join(domains, " "))
	}

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a conta `%s`: %s",
			ev.Username, md["account"], err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` cadastrada com sucesso",
			ev.Username, md["account"]))
	}

}

/*
Sets TinyLetter default account.

HandlerName

 tinyletter

RequiredPermission

 tinyletter

Regex

 tinyletter (?P<command>set default account) (?P<account>\\S+)

Usage

 tinyletter set default account <account>
*/
func TinyLetterSetDefaultAccountCommand(md map[string]string, ev *slack.MessageEvent) {

	creds, _ := TinyLetterListAccounts()

	if !ReadmeIOHasAccount(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(creds, "\n")))
		return
	}

	SetHandlerConfig("tinyletter", "default_account", md["account"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Conta padrão setada para `%s`",
		ev.Username, md["account"]))
}

func TinyLetterHasAccount(account string) bool {
	creds, err := TinyLetterListAccounts()

	if err != nil {
		return false
	}

	if creds == nil {
		return false
	} else {
		if stringInSlice(account, creds) {
			return true
		}
	}

	return false
}

func TinyLetterValidateAccount(md map[string]string) (bool, string) {
	var account = ""

	if val, ok := md["account"]; ok {
		account = val
	} else {
		account, _ = GetHandlerConfig("tinyletter", "default_account")
	}

	if len(account) == 0 {
		return false, account
	}

	return true, account
}

func TinyLetterGetCredentials(account string) (ExternalCredential, error) {
	cred, err := CredentialsGetCredential("tinyletter", account)

	return cred, err
}

/*
Lists account subscribers.

HandlerName

 tinyletter

Regex

 tinyletter (?P<command>list subscribers)

 tinyletter (?P<command>list subscribers) (?P<account>\\S+)

Usage

 tinyletter list subscribers

 tinyletter list subscribers <account>
*/
func TinyLetterListSubscribersCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := TinyLetterValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e aplicação padrão não configurada\n"+
			"Utilize `tinyletter set default account <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !TinyLetterHasAccount(account) {
		creds, _ := TinyLetterListAccounts()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, account, strings.Join(creds, "\n")))
		return
	}

	local_subscribers, _ := GetTrackedUsers("tinyletter", account, "subscribers")

	PostMessage(ev.Channel, fmt.Sprintf("@%s *### Inscritos da conta `%s` ###*:\n%s",
		ev.Username, account, strings.Join(local_subscribers, "\n")))
}

/*
Lists stored accounts.

HandlerName

 tinyletter

Regex

 tinyletter (?P<command>list accounts)

Usage

 tinyletter list accounts
*/
func TinyLetterListAccountsCommand(md map[string]string, ev *slack.MessageEvent) {
	ncreds := TinyLetterGetAccountsWithDefault()

	if ncreds == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhuma conta cadastrada",
			ev.Username))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de contas cadastradas ###*\n%s",
			ev.Username, strings.Join(ncreds, "\n")))
	}
}

func TinyLetterListAccounts() ([]string, error) {
	creds, err := CredentialsListCredentials("tinyletter")

	if err != nil {
		return nil, err
	}

	if len(creds) > 0 {
		var accounts []string

		for _, v := range creds {
			accounts = append(accounts, v.Name)

		}

		return accounts, nil
	} else {
		return nil, nil
	}

}

func TinyLetterIsDomainAllowed(account string, domain string) bool {
	sdomains, _ := GetHandlerConfig("tinyletter", fmt.Sprintf("allowed_domains_%s", account))

	var domains = strings.Split(sdomains, " ")

	if !stringInSlice(domain, domains) {
		return false
	} else {
		return true
	}
}

/*
Sets allowed domains for the specified account.

HandlerName

 tinyletter

RequiredPermission

 tinyletter

Regex

 tinyletter (?P<command>set allowed domains) (?P<account>\\S+) (?P<domains>.*)

Usage

 tinyletter set allowed domains <account> <domains>
*/
func TinyLetterSetAllowedDomainsCommand(md map[string]string, ev *slack.MessageEvent) {

	creds, _ := TinyLetterListAccounts()

	avalid, account := TinyLetterValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e aplicação padrão não configurada\n"+
			"Utilize `tinyletter set default account <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !TinyLetterHasAccount(account) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, account, strings.Join(creds, "\n")))
		return
	}

	var domains []string

	for _, d := range strings.Split(md["domains"], " ") {
		domains = append(domains, StripURL(d))
	}

	SetHandlerConfig("tinyletter", fmt.Sprintf("allowed_domains_%s", account), strings.Join(domains, " "))
	PostMessage(ev.Channel, fmt.Sprintf("@%s Domínios da conta `%s` setados para `%s`",
		ev.Username, account, domains))
}

func TinyLetterGetAccountsWithDefault() []string {
	accounts, _ := TinyLetterListAccounts()

	var naccounts []string

	var def = TinyLetterGetDefaultAccount()
	for _, v := range accounts {
		if v == def {
			naccounts = append(naccounts, fmt.Sprintf("*%s* [default]", v))
		} else {
			naccounts = append(naccounts, v)
		}
	}

	return naccounts
}

func TinyLetterMonitorChanges() {
	for {

		accounts, _ := TinyLetterListAccounts()
		for _, account := range accounts {
			cred, _ := TinyLetterGetCredentials(account)

			s := tiny.Session{}

			s.Username = &cred.Login
			s.Password = &cred.Password

			s.Session = grequests.NewSession(s.GetRequestOptions())

			s.Login()

			var subscribers []string

			local_subscribers, _ := GetTrackedUsers("tinyletter", account, "subscribers")

			rsubscribers, err := s.GetSubscribers("created_at desc", 0, 0)

			if err != nil {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix": "TinyLetterMonitorChanges",
					"caller": caller,
					"file":   file,
					"error":  err.Error(),
				}).Error("An Error Occurred")
				continue
			}

			if !rsubscribers["success"].(bool) {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix":  "TinyLetterMonitorChanges",
					"caller":  caller,
					"file":    file,
					"account": account,
					"error":   "Unauthorized",
				}).Error("An Error Occurred")
				continue
			}

			var added_subscribers []string

			var removed_subscribers []string

			var unauthorized_subscribers []float64

			var unauthorized_subscribers_string []string

			result := rsubscribers["result"].([]interface{})

			for _, v := range result {
				sub := v.(map[string]interface{})["email"].(string)
				id := v.(map[string]interface{})["__id"].(float64)
				subscribers = append(subscribers, sub)
				if !stringInSlice(sub, local_subscribers) {
					TrackUser("tinyletter", account, "subscribers", sub, "INSERT")
					added_subscribers = append(added_subscribers, sub)

				}

				domain := strings.Split(sub, "@")[1]

				if !TinyLetterIsDomainAllowed(account, domain) {
					unauthorized_subscribers = append(unauthorized_subscribers, id)
					unauthorized_subscribers_string = append(unauthorized_subscribers_string, sub)

				}
			}

			if len(added_subscribers) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[TINYLETTER] Inscritos adicionados na conta `%s`: %s", account, added_subscribers))
			}

			for _, v := range local_subscribers {
				if !stringInSlice(v, subscribers) {
					removed_subscribers = append(removed_subscribers, v)
					TrackUser("tinyletter", account, "subscribers", v, "DELETE")
				}
			}

			if len(removed_subscribers) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[TINYLETTER] Inscritos removidos da conta `%s`: %s", account, strings.Join(removed_subscribers, " ")))
			}

			if len(unauthorized_subscribers) > 0 {
				for _, sub := range unauthorized_subscribers {
					var l []float64
					l = append(l, sub)
					_, err := s.DeleteSubscribers(l)

					if err != nil {
						caller, file := GetCaller()
						logger.WithFields(logrus.Fields{
							"prefix": "TinyLetterMonitorChanges",
							"caller": caller,
							"file":   file,
							"error":  err.Error(),
						}).Error("An Error Occurred")
					}

				}

				for _, sub := range unauthorized_subscribers_string {
					TrackUser("tinyletter", account, "subscribers", sub, "DELETE")
				}

				PostMessage(logs_channel, fmt.Sprintf("[TINYLETTER] Inscritos removidos da conta `%s` "+
					"por não estarem autorizados: %s", account, strings.Join(unauthorized_subscribers_string, " ")))
			}

		}

		time.Sleep(time.Duration(60 * time.Second))
	}
}

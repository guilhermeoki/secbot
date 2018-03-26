package main

import (
	"encoding/json"
	"fmt"
	"github.com/levigross/grequests"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
	"time"
)

func ReadmeIOHandlerStart() {

	RegisterHandler("readmeio")

	AddCommand(Command{
		Regex:       regexp.MustCompile("readmeio (?P<command>list accounts)"),
		Help:        "Obtém a lista de contas cadastradas",
		Usage:       "readmeio list accounts",
		Handler:     ReadmeIOListAccountsCommand,
		HandlerName: "readmeio"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("readmeio (?P<command>list pages)"),
		Help:        "Obtém a lista de páginas",
		Usage:       "readmeio list pages",
		Handler:     ReadmeIOListPagesCommand,
		HandlerName: "readmeio"})

	AddCommand(Command{
		Regex:       regexp.MustCompile("readmeio (?P<command>list changes) (?P<slug>\\S+)"),
		Help:        "Obtém lista de mudanças da <slug>",
		Usage:       "readmeio list changes <slug>",
		Handler:     ReadmeIOListChangesCommand,
		HandlerName: "readmeio",
		Parameters: map[string]string{
			"slug": "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("readmeio (?P<account>\\S+) (?P<command>list pages)"),
		Help:        "Obtém a lista de páginas da conta <account>",
		Usage:       "readmeio <account> list pages",
		Handler:     ReadmeIOListPagesCommand,
		HandlerName: "readmeio",
		Parameters: map[string]string{
			"account": "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("readmeio (?P<account>\\S+) (?P<command>list changes) (?P<slug>\\S+)"),
		Help:        "Obtém lista de mudanças da <slug> da conta <account>",
		Usage:       "readmeio <account> list changes <slug>",
		Handler:     ReadmeIOListChangesCommand,
		HandlerName: "readmeio",
		Parameters: map[string]string{
			"account": "\\S+",
			"slug":    "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("readmeio (?P<command>set default account) (?P<account>\\S+)"),
		Help:               "Define a conta padrão do ReadmeIO",
		Usage:              "readmeio set default account <account>",
		Handler:            ReadmeIOSetDefaultAccountCommand,
		RequiredPermission: "readmeio",
		HandlerName:        "readmeio",
		Parameters: map[string]string{
			"account": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("readmeio (?P<command>set account) (?P<account>\\S+) (?P<login>\\S+) (?P<password>\\S+)"),
		Help:               "Seta a conta <account> com os dados informados",
		Usage:              "readmeio set account <account> <login> <password>",
		Handler:            ReadmeIOSetAccountCommand,
		RequiredPermission: "readmeio",
		HandlerName:        "readmeio",
		Parameters: map[string]string{
			"account":  "\\S+",
			"login":    "\\S+",
			"password": "\\S+",
		}})

	go ReadmeIOMonitorChanges()
}

type Project struct {
	ID        string  `json:"_id"'`
	Stable    Version `json:"stable"`
	SubDomain string  `json:"subdomain"`
}

type Version struct {
	ID      string `json:"_id"'`
	Project string `json:"project"`
	Version string `json:"version"`
}

type ProjectData struct {
	Project  Project   `json:"$$project"`
	Version  Version   `json:"$$version"`
	Docs     []Doc     `json:"$$docs"`
	Versions []Version `json:"$$versions"`
}

type Doc struct {
	ID      string `json:"_id"'`
	Title   string `json:"title"`
	Project string `json:"project"`
	Slug    string `json:"slug"`
	Version string `json:"version"`
	Pages   []Page `json:"pages"`
}

type Page struct {
	ID        string     `json:"_id"'`
	Title     string     `json:"title"`
	Slug      string     `json:"slug"`
	CreatedAt *time.Time `json:"createdAt"`
}

type PageHistory struct {
	ID        string          `json:"_id"'`
	Project   string          `json:"project"`
	User      PageHistoryUser `json:"user"`
	CreatedAt *time.Time      `json:"createdAt"`
}

type PageHistoryUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func ReadmeIOHasAccount(account string) bool {
	creds, err := ReadmeIOListAccounts()

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

func ReadmeIOValidateAccount(md map[string]string) (bool, string) {
	var account = ""

	if val, ok := md["account"]; ok {
		account = val
	} else {
		account, _ = GetHandlerConfig("readmeio", "default_account")
	}

	if len(account) == 0 {
		return false, account
	}

	return true, account
}

func ReadmeIOSetDefaultAccountCommand(md map[string]string, ev *slack.MessageEvent) {

	creds, _ := ReadmeIOListAccounts()

	if !ReadmeIOHasAccount(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(creds, "\n")))
		return
	}

	SetHandlerConfig("readmeio", "default_account", md["account"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Conta padrão setada para `%s`",
		ev.Username, md["account"]))
}

func ReadmeIOListChangesCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := ReadmeIOValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e aplicação padrão não configurada\n"+
			"Utilize `readmeio set default account <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !ReadmeIOHasAccount(account) {
		creds, _ := ReadmeIOListAccounts()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, account, strings.Join(creds, "\n")))
		return
	}

	local_changes, _ := GetTrackedData("readmeio", account, md["slug"])

	PostMessage(ev.Channel, fmt.Sprintf("@%s *### Mudanças do slug `%s` da conta `%s` ###*:\n%s",
		ev.Username, md["slug"], account, strings.Join(strings.Split(local_changes, " "), "\n")))
}

func ReadmeIOListPagesCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := ReadmeIOValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e aplicação padrão não configurada\n"+
			"Utilize `readmeio set default account <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !ReadmeIOHasAccount(account) {
		creds, _ := ReadmeIOListAccounts()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, account, strings.Join(creds, "\n")))
		return
	}

	local_pages, _ := ListTrackedData("readmeio", account)

	PostMessage(ev.Channel, fmt.Sprintf("@%s *### Páginas na conta `%s` ###*:\n%s", ev.Username, account, strings.Join(local_pages, "\n")))
}

func ReadmeIOListAccountsCommand(md map[string]string, ev *slack.MessageEvent) {
	ncreds := ReadmeIOGetAccountsWithDefault()

	if ncreds == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhuma conta cadastrada",
			ev.Username))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de contas cadastradas ###*\n%s",
			ev.Username, strings.Join(ncreds, "\n")))
	}
}

func ReadmeIOListAccounts() ([]string, error) {
	creds, err := CredentialsListCredentials("readmeio")

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

func ReadmeIOGetAccountsWithDefault() []string {
	accounts, _ := ReadmeIOListAccounts()

	var naccounts []string

	var def = ReadmeIOGetDefaultAccount()
	for _, v := range accounts {
		if v == def {
			naccounts = append(naccounts, fmt.Sprintf("*%s* [default]", v))
		} else {
			naccounts = append(naccounts, v)
		}
	}

	return naccounts
}

func ReadmeIOGetDefaultAccount() string {

	account, _ := GetHandlerConfig("readmeio", "default_account")

	if len(account) == 0 {
		return ""
	}

	return account

}

func ReadmeIOSetAccountCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	var ex ExternalCredential

	ex.Module = "readmeio"
	ex.Name = md["account"]

	if _, ok := md["token"]; ok {
		ex.Login = md["token"]
	} else {
		ex.Login = StripMailTo(md["login"])
		ex.Password = md["password"]
	}

	err := CredentialsSetCredential(ex)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a conta `%s`: %s",
			ev.Username, md["account"], err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` cadastrada com sucesso",
			ev.Username, md["account"]))
	}

}

func ReadmeIOGetCredentials(account string) (ExternalCredential, error) {
	cred, err := CredentialsGetCredential("readmeio", account)

	return cred, err
}

func ReadmeIOMonitorChanges() {

	for {

		accounts, _ := ReadmeIOListAccounts()

		for _, account := range accounts {
			cred, _ := ReadmeIOGetCredentials(account)

			var local_slug_changes []string

			session := grequests.NewSession(&grequests.RequestOptions{UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"})

			session.Get("https://dash.readme.io", session.RequestOptions)

			session.Get("https://dash.readme.io/login", session.RequestOptions)

			var data = make(map[string]string)

			data["_csrf"] = "undefined"
			data["email"] = cred.Login
			data["password"] = cred.Password

			var opts = grequests.RequestOptions{Data: data}

			resp, err := session.Post("https://dash.readme.io/users/session",
				&opts)

			session.Get("https://dash.readme.io", session.RequestOptions)

			if err != nil {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix": "ReadmeIOMonitorChanges",
					"caller": caller,
					"file":   file,
					"error":  err.Error(),
				}).Error("An Error Occurred")
				continue
			}

			resp, err = session.Get("https://dash.readme.io/api/projects", session.RequestOptions)

			resp.Bytes()

			var projects []Project

			json.Unmarshal(resp.Bytes(), &projects)

			for _, project := range projects {

				var projectdata ProjectData

				url := fmt.Sprintf("https://dash.readme.io/api/projects/%s/v%s/data", project.SubDomain, project.Stable.Version)

				resp, _ := session.Get(url, nil)

				json.Unmarshal(resp.Bytes(), &projectdata)

				for _, version := range projectdata.Versions {
					url = fmt.Sprintf("https://dash.readme.io/api/projects/%s/v%s/data", project.SubDomain, version.Version)

					var versiondata ProjectData

					resp, _ := session.Get(url, nil)

					json.Unmarshal(resp.Bytes(), &versiondata)

					for _, doc := range versiondata.Docs {
						for _, page := range doc.Pages {
							url = fmt.Sprintf("https://dash.readme.io/api/projects/pagarme/history/%s", page.ID)

							var pagehistories []PageHistory

							resp, _ := session.Get(url, nil)

							json.Unmarshal(resp.Bytes(), &pagehistories)

							var tracked_data, _ = GetTrackedData("readmeio", account, page.ID)

							local_slug_changes = strings.Split(tracked_data, " ")

							var slug_changes []string

							copy(local_slug_changes, slug_changes)

							for _, change := range pagehistories {
								if !stringInSlice(change.ID, local_slug_changes) {
									slug_changes = append(slug_changes, change.ID)
									page_url := fmt.Sprintf("https://dash.readme.io/project/%s/v%s/docs/%s", project.SubDomain, version.Version, page.Slug)
									go PostMessage(logs_channel, fmt.Sprintf("Alteração na documentação da versão %s: Página `%s` (%s) editada por `%s` (%s) @ %s'.",
										version.Version, page.Title, page_url, change.User.Name, change.User.Email, change.CreatedAt.String()))
								}
							}
							TrackData("readmeio", account, page.ID, strings.Join(slug_changes, " "), "INSERT")

						}
					}
				}

			}
			time.Sleep(300 * time.Second)
		}
	}
}

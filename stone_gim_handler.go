package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/nlopes/slack"
	"net/http"
	"regexp"
	"strings"
)

func StoneGIMHandlerStart() {

	RegisterHandler("gim")

	AddCommand(Command{
		Regex:       regexp.MustCompile("gim (?P<command>list applications)"),
		Help:        "Lista as aplicações disponíveis",
		Usage:       "gim list applications",
		Handler:     GIMListApplicationsCommand,
		HandlerName: "gim"})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<application>\\S+) (?P<command>recover) (?P<users>.*)"),
		Help:               "Envia email de recuperação de senha para <users> da aplicação <application>",
		Usage:              "gim <application> recover <users>",
		Handler:            GIMRecoverCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
			"users":       ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>recover) (?P<users>.*)"),
		Help:               "Envia email de recuperação de senha para <users> da aplicação <application>",
		Usage:              "gim recover <users>",
		Handler:            GIMRecoverCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"users": ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>set default application) (?P<application>\\S+)"),
		Help:               "Define a aplicação padrão do GIM",
		Usage:              "gim set default application <application>",
		Handler:            GIMSetDefaultApplicationCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("gim (?P<command>set application) (?P<application>\\S+) (?P<key>\\S+) (?P<api_key>\\S+)"),
		Help:               "Seta a aplicação <application> com os dados informados",
		Usage:              "gim set application <application> <key> <api_key>",
		Handler:            GIMSetApplicationCommand,
		RequiredPermission: "gim",
		HandlerName:        "gim",
		Parameters: map[string]string{
			"application": "\\S+",
			"key":         "\\S+",
			"api_key":     "\\S+",
		}})
}

func GIMHasApplication(application string) bool {
	creds, err := GIMListApplications()

	if err != nil {
		return false
	}

	if creds == nil {
		return false
	} else {
		if stringInSlice(application, creds) {
			return true
		}
	}

	return false
}

func GIMSetDefaultApplicationCommand(md map[string]string, ev *slack.MessageEvent) {
	creds, _ := GIMListApplications()

	if !GIMHasApplication(md["application"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["application"], strings.Join(creds, "\n")))
		return
	}

	SetHandlerConfig("gim", "default_application", md["application"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação padrão setada para `%s`",
		ev.Username, md["application"]))
}

func GIMValidateApplication(md map[string]string) (bool, string) {
	var application = ""

	if val, ok := md["application"]; ok {
		application = val
	} else {
		application, _ = GetHandlerConfig("gim", "default_application")
	}

	if len(application) == 0 {
		return false, application
	}

	return true, application
}

func GIMRecoverCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, application := GIMValidateApplication(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma aplicação especificada e aplicação padrão não configurada\n"+
			"Utilize `gim set default application <application>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	cred, err := GIMGetCredentials(application)

	if err == sql.ErrNoRows {
		creds, err := GIMListApplications()

		if err != nil {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` não encontrada", ev.Username, application))
		} else {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` não encontrada, os valores possíveis sao:\n%s",
				ev.Username, application, strings.Join(creds, "\n")))
		}
		return
	}

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro obtendo as credenciais da aplicação `%s`: %s", ev.Username, application, err.Error()))
		return
	}
	var users []string

	for _, v := range strings.Split(md["users"], " ") {
		users = append(users, StripMailTo(v))
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Recuperando senha dos seguintes usuários: %s", ev.Username, strings.Join(users, " ")))

	var recovered []string

	var failed []GenericError

	for _, user := range users {
		client := &http.Client{}
		fmt.Printf("https://gim.stone.com.br/api/management/%s/users/%s/password", cred.Login, user)
		req, err := http.NewRequest("GET", fmt.Sprintf("https://gim.stone.com.br/api/management/%s/users/%s/password", cred.Login, user), nil)

		if err != nil {
			failed = append(failed, GenericError{Key: user,
				Error: fmt.Sprintf("Ocorreu um erro resetando a senha do usuário: %s",
					err.Error())})
			continue
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", cred.Password))
		fmt.Println(req.Header)
		resp, err := client.Do(req)

		if resp.StatusCode == 401 {
			failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Permissão negada")})
			continue
		}

		var response map[string]interface{}

		decoder := json.NewDecoder(resp.Body)

		err = decoder.Decode(&response)

		if err != nil {
			failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Ocorreu um erro decodificando"+
				" a resposta do GIM: %s", err.Error())})
			continue
		}

		if response["Success"].(bool) {
			recovered = append(recovered, user)
			continue
		} else {
			var report []interface{}
			report = response["OperationReport"].([]interface{})
			for _, r := range report {
				rep := r.(map[string]interface{})
				if rep["Message"] == "The specified user is not associated to this application." {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Usuário não encontrado na aplicação %s",
						application)})
					continue
				} else if rep["Message"] == "User not found." {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Usuário não encontrado")})
					continue
				} else {
					failed = append(failed, GenericError{Key: user, Error: fmt.Sprintf("Erro resetando a senha: %s",
						rep["Message"])})
					continue
				}
			}
		}

	}

	var msg = fmt.Sprintf("@%s *### Resultado ###*\n", ev.Username)

	if len(recovered) > 0 {
		msg += fmt.Sprintf("*Usuários Recuperados*\n%s", strings.Join(recovered, " "))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	}

	PostMessage(ev.Channel, msg)
}

func GIMGetCredentials(application string) (ExternalCredential, error) {
	cred, err := CredentialsGetCredential("gim", application)

	return cred, err
}

func GIMGetApplicationsWithDefault() []string {
	applications, _ := GIMListApplications()

	var napplications []string

	var def = GIMGetDefaultApplication()
	for _, v := range applications {
		if v == def {
			napplications = append(napplications, fmt.Sprintf("*%s* [default]", v))
		} else {
			napplications = append(napplications, v)
		}
	}

	return napplications
}

func GIMListApplicationsCommand(md map[string]string, ev *slack.MessageEvent) {
	ncreds := GIMGetApplicationsWithDefault()

	if ncreds == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhuma aplicação cadastrada",
			ev.Username))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de aplicações cadastradas ###*\n%s",
			ev.Username, strings.Join(ncreds, "\n")))
	}
}

func GIMListApplications() ([]string, error) {
	creds, err := CredentialsListCredentials("gim")

	if err != nil {
		return nil, err
	}

	if len(creds) > 0 {
		var applications []string

		for _, v := range creds {
			applications = append(applications, v.Name)

		}

		return applications, nil
	} else {
		return nil, nil
	}

}

func GIMGetDefaultApplication() string {

	application, _ := GetHandlerConfig("gim", "default_application")

	if len(application) == 0 {
		return ""
	}

	return application

}

func GIMSetApplicationCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	var ex ExternalCredential

	ex.Module = "gim"
	ex.Name = md["application"]
	ex.Login = md["key"]
	ex.Password = md["api_key"]

	err := CredentialsSetCredential(ex)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a aplicação `%s`: %s",
			ev.Username, md["application"], err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Aplicação `%s` cadastrada com sucesso",
			ev.Username, md["application"]))
	}

}

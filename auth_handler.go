package secbot

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

func AuthHandlerStart() {

	RegisterHandler("auth")

	AddCommand(Command{
		Regex:              regexp.MustCompile("(?P<command>auth add) (?P<permissions>.*) to users (?P<users>.*)"),
		Help:               "Adiciona as permissões <permissions> para os usuários <users>",
		Handler:            AuthAddCommand,
		RequiredPermission: "authorizer",
		HandlerName:        "auth",
		Usage:              "auth add <permissions> to users <users>",
		Parameters: map[string]string{
			"permissions": ".*",
			"users":       ".*",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("(?P<command>auth del) (?P<permissions>.*) to users (?P<users>.*)"),
		Help:               "Remove as permissões <permissions> dos usuários <users>",
		Handler:            AuthDelCommand,
		RequiredPermission: "authorizer",
		HandlerName:        "auth",
		Usage:              "auth del <permissions> to users <users>",
		Parameters: map[string]string{
			"permissions": ".*",
			"users":       ".*",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("(?P<command>auth list)"),
		Help:        "Lista todas as permissões",
		Handler:     AuthListCommand,
		Usage:       "auth list",
		HandlerName: "auth"})

	go SlackGetMembers()
}

func AuthGetSections() ([]string, error) {
	selectStmt := "SELECT section FROM authorization GROUP BY section"

	rows, err := db.Query(selectStmt)

	var setions []string

	defer rows.Close()
	for rows.Next() {
		var section string
		err = rows.Scan(&section)
		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "AuthGetSections",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
		}
		setions = append(setions, section)
	}
	err = rows.Err()
	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetConfig",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Fatal("An Error Occurred")
	}

	return setions, err
}

/*
Lists all permissions.

HandlerName
 auth

Regex

 (?P<command>auth list)

Usage
  auth list
*/
func AuthListCommand(md map[string]string, ev *slack.MessageEvent) {
	sections, _ := AuthGetSections()

	var authlist map[string][]string

	authlist = make(map[string][]string)

	for _, k := range sections {
		authlist[k], _ = AuthGetPermission(k)
	}

	var msg = fmt.Sprintf("@%s\n*### Lista de Permissões ###*\n", ev.Username)

	for k, v := range authlist {
		msg += fmt.Sprintf("\n[%s] %s", k, strings.Join(v, " "))
	}

	PostMessage(ev.Channel, msg)
}

/*
Adds the permissions <permissions> to the users <users>.

HandlerName:

 auth

RequiredPermission:

 authorizer

Regex

 (?P<command>auth add) (?P<permissions>.*) to users (?P<users>.*)

Usage

 auth add <permissions> to users <users>
*/
func AuthAddCommand(md map[string]string, ev *slack.MessageEvent) {

	sections := strings.Split(md["permissions"], " ")
	users := strings.Split(md["users"], " ")

	var added map[string][]string
	added = make(map[string][]string)

	var alreadyexists map[string][]string
	alreadyexists = make(map[string][]string)

	var errored map[string][]string
	errored = make(map[string][]string)

	for _, section := range sections {
		for _, user := range users {
			exists, err := AuthAddPermission(section, user)

			if !exists && err == nil {
				added[section] = append(added[section], user)
			} else if exists && err == nil {
				alreadyexists[section] = append(alreadyexists[section], user)
			} else if err != nil {
				errored[section] = append(errored[section], user)
			}
		}
	}

	var msg = fmt.Sprintf("@%s", ev.Username)

	for _, section := range sections {
		msg += fmt.Sprintf("\n*## [%s] ##*\n\n", section)
		if len(added[section]) > 0 {
			msg += fmt.Sprintf("*Adicionado:* %s\n", strings.Join(added[section], " "))
		}
		if len(alreadyexists[section]) > 0 {
			msg += fmt.Sprintf("*Já existe:* %s\n", strings.Join(alreadyexists[section], " "))
		}
		if len(errored[section]) > 0 {
			msg += fmt.Sprintf("*Erro:* %s\n", strings.Join(errored[section], " "))
		}
	}

	PostMessage(ev.Channel, msg)
}

/*
Removes the permissions <permissions> from the users <users>.

HandlerName
 auth


RequiredPermission
 authorizer

Regex

 (?P<command>auth del) (?P<permissions>.*) to users (?P<users>.*)

Usage

 auth del <permissions> to users <users>
*/
func AuthDelCommand(md map[string]string, ev *slack.MessageEvent) {

	sections := strings.Split(md["permissions"], " ")
	users := strings.Split(md["users"], " ")

	var removed map[string][]string
	removed = make(map[string][]string)

	var notexists map[string][]string
	notexists = make(map[string][]string)

	var errored map[string][]string
	errored = make(map[string][]string)

	for _, section := range sections {
		for _, user := range users {
			exists, err := AuthRemovePermission(section, user)

			if exists && err == nil {
				removed[section] = append(removed[section], user)
			} else if !exists && err == nil {
				notexists[section] = append(notexists[section], user)
			} else if err != nil {
				fmt.Print(err)
				errored[section] = append(errored[section], user)
			}
		}
	}

	var msg = fmt.Sprintf("@%s", ev.Username)

	for _, section := range sections {
		msg += fmt.Sprintf("\n*## [%s] ##*\n", section)
		if len(removed[section]) > 0 {
			msg += fmt.Sprintf("*Removido:* %s\n", strings.Join(removed[section], " "))
		}
		if len(notexists[section]) > 0 {
			msg += fmt.Sprintf("*Não Encontrado:* %s\n", strings.Join(notexists[section], " "))
		}
		if len(errored[section]) > 0 {
			msg += fmt.Sprintf("*Erro:* %s\n", strings.Join(errored[section], " "))
		}
	}

	PostMessage(ev.Channel, msg)

}

func AuthRemovePermission(section string, user string) (bool, error) {
	userExists := IsAuthorized(section, user)

	var err error

	if userExists {
		sqlStmt := "DELETE FROM authorization WHERE section = ? AND user = ?"

		p, err := db.Prepare(sqlStmt)

		p.Exec(section, user)

		return userExists, err

	}

	return userExists, err

}

func AuthAddPermission(section string, user string) (bool, error) {
	userExists := IsAuthorized(section, user)

	var err error

	if !userExists {
		sqlStmt := "INSERT INTO authorization(section, user) VALUES (?,?)"

		p, err := db.Prepare(sqlStmt)

		p.Exec(section, user)

		return userExists, err

	}

	return userExists, err

}

func AuthGetPermission(section string) ([]string, error) {
	selectStmt := "SELECT id, user FROM authorization WHERE section = ?"

	rows, err := db.Query(selectStmt, section)

	var users []string

	defer rows.Close()
	for rows.Next() {
		var id int
		var user string
		err = rows.Scan(&id, &user)
		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "AuthGetPermission",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
		}
		users = append(users, user)
	}
	err = rows.Err()
	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "AuthGetPermission",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Fatal("An Error Occurred")
	}

	return users, err
}

// Checks if a user is authorized
func IsAuthorized(section string, user string) bool {

	if user == masteruser || section == "" {
		return true
	}

	var user_id string

	selectStmt := "SELECT id FROM authorization WHERE section = ? AND user = ?"

	err := db.QueryRow(selectStmt, section, user).Scan(&user_id)

	var userExists bool

	userExists = false

	switch {

	case err == sql.ErrNoRows:

		userExists = false

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "TrackUser",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

	default:

		userExists = true

	}

	return userExists

}

func Unauthorized(md map[string]string, ev *slack.MessageEvent) {
	PostMessage(ev.Channel, fmt.Sprintf("@%s Você não está autorizado a executar o comando `%s`. "+
		"Esse incidente foi logado.", ev.Username, md["command"]))
}

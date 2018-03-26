package secbot

import (
	"database/sql"
	"github.com/sirupsen/logrus"
)

/*
Defines an external credential object, which should be stored using CredentialsSetCredential

See: https://godoc.org/github.com/pagarme/secbot/#CredentialsSetCredential

See: https://godoc.org/github.com/pagarme/secbot/#CredentialsGetCredential
*/
type ExternalCredential struct {
	Module   string
	Name     string
	Login    string
	Password string
}

/*
Lists available credentials for an specific module.

This should be used for listing stored accounts previously set by CredentialsSetCredential().

See: https://godoc.org/github.com/pagarme/secbot/#CredentialsSetCredential
*/
func CredentialsListCredentials(module string) ([]ExternalCredential, error) {
	var creds []ExternalCredential

	selectStmt := "SELECT name, login, password FROM externalcredentials WHERE module = ?"

	rows, err := db.Query(selectStmt, module)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var ex ExternalCredential

		ex.Module = module

		if err := rows.Scan(&ex.Name, &ex.Login, &ex.Password); err == nil {
			creds = append(creds, ex)
		}

	}

	return creds, nil
}

/*
Gets an specific credential.

See: https://godoc.org/github.com/pagarme/secbot/#CredentialsSetCredential
*/
func CredentialsGetCredential(module string, name string) (ExternalCredential, error) {

	var ex ExternalCredential

	ex.Module = module
	ex.Name = name

	selectStmt := "SELECT login, password FROM externalcredentials WHERE module = ? AND name = ?"

	err := db.QueryRow(selectStmt, module, name).Scan(&ex.Login, &ex.Password)

	switch {

	case err == sql.ErrNoRows:

		return ex, err

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetCredentials",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

		return ex, err

	default:

		return ex, nil

	}
}

/*
Sets an external credential, which is stored in the database.
*/
func CredentialsSetCredential(cred ExternalCredential) error {
	var config_id string

	selectStmt := "SELECT id FROM externalcredentials WHERE module = ? AND name = ?"

	err := db.QueryRow(selectStmt, cred.Module, cred.Name).Scan(&config_id)

	var configExists bool

	switch {

	case err == sql.ErrNoRows:

		configExists = false

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "SetCredentials",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

		return err

	default:

		configExists = true

	}

	if configExists {
		sqlStmt := "UPDATE externalcredentials SET login = ?, password = ? WHERE id = ?"

		p, _ := db.Prepare(sqlStmt)

		p.Exec(cred.Login, cred.Password, config_id)

	} else {
		sqlStmt := "INSERT INTO externalcredentials(module, name, login, password) VALUES (?,?,?,?)"

		p, _ := db.Prepare(sqlStmt)

		p.Exec(cred.Module, cred.Name, cred.Login, cred.Password)
	}

	return nil
}

package main

import (
	"database/sql"
	"github.com/sirupsen/logrus"
)

type ExternalCredential struct {
	Module   string
	Name     string
	Login    string
	Password string
}

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

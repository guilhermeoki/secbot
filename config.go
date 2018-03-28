package secbot

import (
	"database/sql"
	"github.com/awnumar/memguard"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
	"os"
	"os/user"
)

var db_file = "./secbot.db"

/*
Initialize the SQLite3 database object.

You should only call this once, and store it as a global variable.

This disables the connection pooling by calling SetMaxOpenConns(1), due to lock limitations on SQLite itself.

Also, synchronous access is turned off and journal is stored in memory.
*/
func GetDB() (*sql.DB, error) {

	dbx, err := sql.Open("sqlite3", db_file)
	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetConfig",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Fatal("An Error Occurred")

		memguard.SafeExit(1)
	}

	dbx.SetMaxOpenConns(1)

	dbx.Exec("PRAGMA synchronous = OFF")
	dbx.Exec("PRAGMA journal_mode = MEMORY")

	return dbx, err
}

/*
This function issues the CREATE TABLE statements required for the bot to function.

This is only called if the database secbot.db isn't found in the working directory.
*/
func Bootstrap() {
	if _, err := os.Stat(db_file); err != nil {

		dbx, _ := GetDB()

		logger.WithFields(logrus.Fields{
			"prefix":   "Bootstrap",
			"database": db_file,
		}).Info("Database not found, bootstraping")

		tx, _ := dbx.Begin()

		sqlStmt := `
	CREATE TABLE authorization (id INTEGER NOT NULL PRIMARY KEY, section TEXT, user TEXT);
	CREATE TABLE usertrack (id INTEGER NOT NULL PRIMARY KEY, module TEXT, name TEXT, section TEXT, user TEXT);
	CREATE TABLE datatrack (id INTEGER NOT NULL PRIMARY KEY, module TEXT, name TEXT, section TEXT, value TEXT);
	CREATE TABLE handlerconfig (id INTEGER NOT NULL PRIMARY KEY, handler TEXT, key TEXT, value TEXT);
	CREATE TABLE externalcredentials (id INTEGER NOT NULL PRIMARY KEY, module TEXT, name TEXT, login TEXT, password TEXT);
	`
		tx.Exec(sqlStmt)

		tx.Commit()

		dbx.Close()
	}
}

/*
Gets the handlers specified config value, previously set by SetHandlerConfig().

See: https://godoc.org/github.com/pagarme/secbot/#SetHandlerConfig
*/
func GetHandlerConfig(handler string, key string) (string, error) {
	var config_id string
	var value string

	selectStmt := "SELECT id, value FROM handlerconfig WHERE handler = ? AND key = ?"

	err := db.QueryRow(selectStmt, handler, key).Scan(&config_id, &value)

	switch {

	case err == sql.ErrNoRows:

		return "", err

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetHandlerConfig",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

		return "", err

	default:

		return value, nil

	}
}

/*
Sets the handlers specified config value, which can later be acessed with GetHandlerConfig().

See: https://godoc.org/github.com/pagarme/secbot/#GetHandlerConfig
*/
func SetHandlerConfig(handler string, key string, value string) {
	var config_id string

	selectStmt := "SELECT id FROM handlerconfig WHERE handler = ? AND key = ?"

	err := db.QueryRow(selectStmt, handler, key).Scan(&config_id)

	var configExists bool

	switch {

	case err == sql.ErrNoRows:

		configExists = false

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "SetHandlerConfig",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

		return

	default:

		configExists = true

	}

	if configExists {
		sqlStmt := "UPDATE handlerconfig SET value = ? WHERE id = ?"

		p, _ := db.Prepare(sqlStmt)

		p.Exec(value, config_id)

	} else {
		sqlStmt := "INSERT INTO handlerconfig(handler, key, value) VALUES (?,?,?)"

		p, _ := db.Prepare(sqlStmt)

		p.Exec(handler, key, value)
	}
}

/*
Gets a list of tracked users, previously set with TrackUser().

See: https://godoc.org/github.com/pagarme/secbot/#TrackUser
*/
func GetTrackedUsers(module string, name string, section string) ([]string, error) {

	selectStmt := "SELECT id, user FROM usertrack WHERE module = ? AND name = ? AND section = ?"

	rows, err := db.Query(selectStmt, module, name, section)

	var users []string

	defer rows.Close()
	for rows.Next() {
		var id int
		var user string
		err = rows.Scan(&id, &user)
		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "GetTrackedUsers",
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
			"prefix": "GetTrackedUsers",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Fatal("An Error Occurred")
	}

	return users, err

}

/*
Tracks a user, which can later be accessed with GetTrackedUsers().

<action> should be either INSERT or DELETE.

See: https://godoc.org/github.com/pagarme/secbot/#GetTrackedUsers
*/
func TrackUser(module string, name string, section string, user string, action string) {

	var user_id string

	selectStmt := "SELECT id FROM usertrack WHERE module = ? AND name = ? AND section = ? AND user = ?"

	err := db.QueryRow(selectStmt, module, name, section, user).Scan(&user_id)

	var userExists bool

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

	if action == "DELETE" {
		if userExists {
			sqlStmt := "DELETE FROM usertrack WHERE id = ?"

			db.Exec(sqlStmt, user_id)
		}

	} else if action == "INSERT" {
		if !userExists {
			sqlStmt := "INSERT INTO usertrack(module, name, section, user) VALUES (?,?,?,?)"

			p, _ := db.Prepare(sqlStmt)

			p.Exec(module, name, section, user)

		}

	}

}

/*
List data sections previously tracked by TrackData()

See: https://godoc.org/github.com/pagarme/secbot/#TrackData
*/
func ListTrackedData(module string, name string) ([]string, error) {

	selectStmt := "SELECT id, section FROM datatrack WHERE module = ? AND name = ?"

	rows, err := db.Query(selectStmt, module, name)

	var data []string

	defer rows.Close()
	for rows.Next() {
		var id int
		var d string
		err = rows.Scan(&id, &d)
		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "ListTrackedData",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
		}
		data = append(data, d)
	}
	err = rows.Err()
	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "ListTrackedData",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Fatal("An Error Occurred")
	}

	return data, err

}

/*
List data previously tracked by TrackData().

See: https://godoc.org/github.com/pagarme/secbot/#TrackData
*/
func GetTrackedData(module string, name string, section string) (string, error) {

	var value string

	selectStmt := "SELECT value FROM datatrack WHERE module = ? AND name = ? AND section = ?"

	err := db.QueryRow(selectStmt, module, name, section).Scan(&value)

	if err == sql.ErrNoRows {
		return "", nil
	}

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetTrackedData",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

		return "", err
	}

	return value, nil
}

/*
Tracks handlers abstract data.

You should use this when dealing with a large amount of values, since it stores everything in the same row, reducing the number of scans.

you should Split() and Join() the values if necessary. Usually, a blank space is used as separator, but feel free to use anything you want.

See: https://godoc.org/github.com/pagarme/secbot/#ListTrackedData

See: https://godoc.org/github.com/pagarme/secbot/#GetTrackedData
*/
func TrackData(module string, name string, section string, value string, action string) {

	var data_id string

	selectStmt := "SELECT id FROM datatrack WHERE module = ? AND name = ? AND section = ?"

	err := db.QueryRow(selectStmt, module, name, section).Scan(&data_id)

	var userExists bool

	switch {

	case err == sql.ErrNoRows:

		userExists = false

	case err != nil:

		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "TrackData",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")

	default:

		userExists = true

	}

	if action == "DELETE" {
		if userExists {
			sqlStmt := "DELETE FROM datatrack WHERE id = ?"

			db.Exec(sqlStmt, data_id)
		}

	} else if action == "INSERT" {
		if !userExists {
			sqlStmt := "INSERT INTO datatrack(module, name, section, value) VALUES (?,?,?,?)"

			p, _ := db.Prepare(sqlStmt)

			p.Exec(module, name, section, value)

		} else {
			sqlStmt := "UPDATE datatrack SET value = ? WHERE module = ? AND section = ? AND name = ?"

			p, _ := db.Prepare(sqlStmt)

			p.Exec(value, module, section, name)
		}

	}

}

/*
Simple function to get the current user's home directory.
*/
func GetHome() string {
	usr, err := user.Current()

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetHome",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

	return usr.HomeDir
}

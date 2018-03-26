package secbot

import "github.com/sirupsen/logrus"

func ExampleGetCaller() (string, string) {
	var err error

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "ExampleGetCaller",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}
}

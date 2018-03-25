package main

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	es "github.com/elastic/go-elasticsearch/client"
	"fmt"
)

var logging_endpoint = ""
var logging_client *es.Client

func LoggingInterceptorStart() {

	logger.WithFields(logrus.Fields{
		"handler": "logging",
	}).Info("Starting Interceptor")

	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		".*"), Handler: LoggingInterceptor})
	AddCommand(Command{Regex: regexp.MustCompile("logging (?P<command>set endpoint) (?P<endpoint>\\S+)"),
		Help: "Define o endpoint de logs", Handler: LoggingSetEndpointCommand})

	logging_endpoint, _ = GetHandlerConfig("logging", "endpoint")
	logging_client, _ = es.New(es.WithHost(logging_endpoint))

}

func LoggingInterceptor(md map[string]string, ev *slack.MessageEvent) {

	// Check global variable to reduce database access
	if len(logging_endpoint) == 0 {
		return
	}

	doc := map[string]interface{}{
		"channel":         ev.Channel,
		"username":        ev.Username,
		"@timestamp":      ev.Timestamp,
		"threadTimestamp": ev.ThreadTimestamp,
		"text":            ev.Text,
		"team":            ev.Team,
		"messageType":     ev.Type,
	}

	go logging_client.Index("logs", "message", doc)

}

func LoggingSetEndpointCommand(md map[string]string, ev *slack.MessageEvent) {

	SetHandlerConfig("logging", "endpoint", md["endpoint"])

	logging_endpoint = md["endpoint"]
	logging_client, _ = es.New(es.WithHost(logging_endpoint))

	PostMessage(ev.Channel, fmt.Sprintf("@%s Endpoint setado para `%s`",
		ev.Username, md["endpoint"]))

}

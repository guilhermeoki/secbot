package main

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	"gopkg.in/olivere/elastic.v6"
	"fmt"
	"context"
	"errors"
	"strconv"
	"time"
	"strings"
)

var logging_endpoint = ""
var logging_client *elastic.Client
var logging_index = "slack"

var logging_ctx = context.Background()

// Tweet is a structure used for serializing/deserializing data in Elasticsearch.
type LoggingSlackMessage struct {
	Channel         string    `json:"channel"`
	ChannelId       string    `json:"channelId"`
	UserId          string    `json:"userId"`
	Username        string    `json:"username"`
	Text            string    `json:"text"`
	Team            string    `json:"team"`
	Timestamp       time.Time `json:"timestamp"`
	ThreadTimestamp time.Time `json:"threadTimestamp,omitempty"`
	Type            string    `json:"type"`
	PrivateChannel  bool      `json:"privateChannel"`
}

const slack_mapping = `
{
	"settings":{
		"number_of_shards": 1,
		"number_of_replicas": 0
	},
	"mappings":{
		"slackmessage":{
			"properties":{
				"channelId":{
					"type":"keyword"
				},
				"channel":{
					"type":"keyword"
				},
				"userId":{
					"type":"keyword"
				},
				"username":{
					"type":"keyword"
				},
				"text":{
					"type":"text",
					"store": true,
					"fielddata": true
				},
				"team":{
					"type":"keyword"
				},
				"timestamp":{
					"type":"date"
				},
				"threadTimestamp":{
					"type":"date"
				},
				"type":{
					"type":"keyword"
				},
				"privateChannel":{
					"type":"boolean"
				},
			}
		}
	}
}`

func LoggingInterceptorStart() {

	logger.WithFields(logrus.Fields{
		"handler": "logging",
	}).Info("Starting Interceptor")

	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		".*"), Handler: LoggingInterceptor})
	AddCommand(Command{Regex: regexp.MustCompile("logging (?P<command>set endpoint) (?P<endpoint>\\S+)"),
		Help: "Define o endpoint de logs", Handler: LoggingSetEndpointCommand})

	var err error

	logging_endpoint, _ = GetHandlerConfig("logging", "endpoint")
	logging_client, err = LoggingGetClient(logging_endpoint)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "LoggingInterceptorStart",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	} else {
		LoggingCreateIndex(logging_index, slack_mapping)
	}

}

func LoggingCreateIndex(index string, mapping string) (bool, error) {

	exists, err := logging_client.IndexExists(index).Do(context.Background())

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "LoggingCreateIndex",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
		return exists, err
	}

	if !exists {
		createIndex, err := logging_client.CreateIndex(index).BodyString(mapping).Do(logging_ctx)

		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "LoggingCreateIndex",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
			return exists, err
		}

		if !createIndex.Acknowledged {
			return exists, errors.New("not acked")
		}
	}

	return exists, err

}

func LoggingInterceptor(md map[string]string, ev *slack.MessageEvent) {

	// Check global variable to reduce database access
	if len(logging_endpoint) == 0 || logging_client == nil {
		return
	}

	// Dont log private messages
	if strings.HasPrefix(ev.Channel, "D") {
		return
	}

	var timestamp_1, _ = strconv.ParseInt(strings.Split(ev.Timestamp, ".")[0], 10, 64)
	var timestamp_2, _ = strconv.ParseInt(strings.Split(ev.Timestamp, ".")[1], 10, 64)

	var threadtimestamp_1 int64
	var threadtimestamp_2 int64

	threadtimestamp_1 = 0
	threadtimestamp_2 = 0

	if len(ev.ThreadTimestamp) > 0 {
		threadtimestamp_1, _ = strconv.ParseInt(strings.Split(ev.ThreadTimestamp, ".")[0], 10, 64)
		threadtimestamp_2, _ = strconv.ParseInt(strings.Split(ev.ThreadTimestamp, ".")[1], 10, 64)
	}

	var channel string

	var isPrivate bool

	if strings.HasPrefix(ev.Channel, "G") {
		gr, _ := GetGroup(ev.Channel)
		channel = gr.Name
		isPrivate = true
	} else {
		ch, _ := GetChannel(ev.Channel)
		channel = ch.Name
		isPrivate = false
	}

	timestamp := time.Unix(timestamp_1, timestamp_2)
	threadtimestamp := time.Unix(threadtimestamp_1, threadtimestamp_2)

	doc := LoggingSlackMessage{
		ChannelId:       ev.Channel,
		Channel:         channel,
		UserId:          ev.User,
		Username:        ev.Username,
		Timestamp:       timestamp,
		ThreadTimestamp: threadtimestamp,
		Text:            ev.Text,
		Team:            ev.Team,
		Type:            ev.Type,
		PrivateChannel:  isPrivate,
	}

	_, err := logging_client.Index().
		Index(logging_index).
		Type("slackmessage").
		BodyJson(doc).
		Do(logging_ctx)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "LoggingInterceptor",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

}

func LoggingGetClient(endpoint string) (*elastic.Client, error) {
	scheme := strings.Split(endpoint, ":")[0]
	return elastic.NewClient(elastic.SetURL(endpoint), elastic.SetScheme(scheme), elastic.SetSniff(false))
}

func LoggingSetEndpointCommand(md map[string]string, ev *slack.MessageEvent) {

	end := StripURL(md["endpoint"])

	eclient, err := LoggingGetClient(end)

	if err == nil {
		logging_endpoint = end

		SetHandlerConfig("logging", "endpoint", logging_endpoint)

		logging_client = eclient

		PostMessage(ev.Channel, fmt.Sprintf("@%s Endpoint setado para `%s`",
			ev.Username, logging_endpoint))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro setando o endpoint para `%s`: %s",
			ev.Username, end, err.Error()))
	}

}

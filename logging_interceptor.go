package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"gopkg.in/olivere/elastic.v6"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	AddInterceptor(Interceptor{
		Regex: regexp.MustCompile(
			".*"),
		Handler:  LoggingInterceptor,
		Continue: true})
	AddCommand(Command{
		Regex:   regexp.MustCompile("logging (?P<command>set endpoint) (?P<endpoint>\\S+)"),
		Help:    "Define o endpoint de logs",
		Handler: LoggingSetEndpointCommand})
	AddCommand(Command{
		Regex:   regexp.MustCompile("logging (?P<command>get logs) (?P<channel>\\S+) (?P<start_date>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}) (?P<end_date>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})"),
		Help:    "Obtém logs do intervalo especificado",
		Handler: LoggingGetLogCommand})
	AddCommand(Command{
		Regex:   regexp.MustCompile("logging (?P<command>get logs) (?P<channel>\\S+) (?P<match>.*) (?P<start_date>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}) (?P<end_date>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})"),
		Help:    "Obtém logs do intervalo especificado que contenham o texto <match>",
		Handler: LoggingGetLogCommand})

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
	} else if strings.HasPrefix(ev.Channel, "C") {
		ch, _ := GetChannel(ev.Channel)
		channel = ch.Name
		isPrivate = false
	} else {
		return
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

func LoggingGetLogCommand(md map[string]string, ev *slack.MessageEvent) {

	if len(logging_endpoint) == 0 || logging_client == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Não foi possível obter uma conexão com o endpoint", ev.Username))
		return
	}

	var channel slack.Channel
	var group slack.Group

	var members []string

	channels, _ := api.GetChannels(false)

	for _, ch := range channels {
		if ch.Name == md["channel"] {
			channel, _ := GetChannel(ch.ID)
			members = channel.Members
			break
		}
	}

	groups, _ := api.GetGroups(false)

	for _, gr := range groups {
		if gr.Name == md["channel"] {
			group, _ := GetGroup(gr.ID)
			members = group.Members
			break
		}
	}

	if &channel == nil && &group == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Canal `%s` não encontrado", ev.Username, md["channel"]))
		return
	}

	if !stringInSlice(ev.User, members) {
		fmt.Println(ev.User)
		fmt.Println(members)
		Unauthorized(md, ev)
		return
	}

	termQuery := elastic.NewTermQuery("channel", md["channel"])

	rangeQuery := elastic.NewRangeQuery("timestamp")

	start, _ := time.Parse("2006-01-02T15:04:05", md["start_date"])
	end, _ := time.Parse("2006-01-02T15:04:05", md["end_date"])

	rangeQuery.Gte(start.Format("2006-01-02T15:04:05.000Z"))
	rangeQuery.Lte(end.Format("2006-01-02T15:04:05.000Z"))
	rangeQuery.TimeZone("-03:00")

	query := elastic.NewBoolQuery()

	query = query.Must(termQuery)
	query = query.Must(rangeQuery)

	if val, ok := md["match"]; ok {
		wildcardQuery := elastic.NewWildcardQuery("text", fmt.Sprintf("*%s*", val))
		query = query.Must(wildcardQuery)
	}

	searchResult, err := logging_client.Search().
		Index(logging_index).    // search in index "tweets"
		Query(query).            // specify the query
		Sort("timestamp", true). // sort by "user" field, ascending
		From(0).Size(10).        // take documents 0-9
		Pretty(true).            // pretty print request and response JSON
		Do(context.Background()) // execute
	if err != nil {
		// Handle error
		panic(err)
	}

	if searchResult.TotalHits() == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhum resultado encontrado",
			ev.Username))
		return
	}

	var results []string

	for _, hit := range searchResult.Hits.Hits {
		// hit.Index contains the name of the index

		// Deserialize hit.Source into a Tweet (could also be just a map[string]interface{}).
		var t LoggingSlackMessage
		err := json.Unmarshal(*hit.Source, &t)
		if err != nil {
			// Deserialization failed
		}

		// Work with tweet

		results = append(results, fmt.Sprintf("[%s] %s: %s", t.Timestamp, t.Username, t.Text))
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s %d resultados encontrados em %d milisegundos",
		ev.Username, len(results), searchResult.TookInMillis))

	var share_channels []string
	share_channels = append(share_channels, ev.Channel)

	params := slack.FileUploadParameters{
		Title:    fmt.Sprintf("Logs for channel #%s, from %s to %s.txt", md["channel"], start.Format("2006-01-02T15:04:05.000Z"), end.Format("2006-01-02T15:04:05.000Z")),
		Filetype: "txt",
		File:     fmt.Sprintf("%s_%s_%s.txt", md["channel"], start.Format("2006-01-02T15:04:05"), end.Format("2006-01-02T15:04:05")),
		Content:  strings.Join(results, "\n"),
		Channels: share_channels,
	}

	api.UploadFile(params)
}

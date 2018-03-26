package main

import (
	"fmt"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

var slack_group_map = make(map[string]*slack.Group)
var slack_channel_map = make(map[string]*slack.Channel)
var slack_user_map = make(map[string]*slack.User)

func AtBot(message string) bool {
	if strings.HasPrefix(message, fmt.Sprintf("<@%s>", botid)) {
		return true
	}
	return false
}

func GetGroup(id string) (*slack.Group, error) {

	if val, ok := slack_group_map[id]; ok {
		return val, nil
	}

	group, err := api.GetGroupInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetGroup",
			"caller": caller,
			"file":   file,
			"group":  id,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

	slack_group_map[id] = group

	return group, err
}

func GetChannel(id string) (*slack.Channel, error) {

	if val, ok := slack_channel_map[id]; ok {
		return val, nil
	}

	channel, err := api.GetChannelInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix":  "GetChannel",
			"caller":  caller,
			"file":    file,
			"channel": id,
			"error":   err.Error(),
		}).Error("An Error Occurred")
	}

	slack_channel_map[id] = channel

	return channel, err
}

func GetUser(id string) (*slack.User, error) {
	if val, ok := slack_user_map[id]; ok {
		return val, nil
	}

	user, err := api.GetUserInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetUser",
			"caller": caller,
			"file":   file,
			"user":   id,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

	slack_user_map[id] = user

	return user, err
}

func GetID() (string, error) {
	users, err := api.GetUsers()

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetID",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
		return "", err
	}

	for _, user := range users {
		if user.Name == botname {
			return user.ID, nil
		}

	}

	return "", nil
}

func JoinChannels() {
	for {
		channels, err := api.GetChannels(true)

		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "JoinChannels",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
			continue
		}

		for _, channel := range channels {
			if !channel.IsMember {

				logger.WithFields(logrus.Fields{
					"prefix":  "JoinChannels",
					"channel": channel.Name,
				}).Info("Joining Channel")

				api.JoinChannel(channel.Name)

				//api.PostMessage(channel.Name, "Every move you make\nEvery step you take\nI'll be watching you", slack.PostMessageParameters{AsUser: true})
			}
		}

		time.Sleep(60 * time.Second)

	}

}

func PostMessage(channel string, message string) {
	api.PostMessage(channel, message, slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true})

}

func PostEphemeralMessage(channel string, user string, message string) {
	params := slack.NewPostMessageParameters()

	api.PostEphemeral(channel, user, slack.MsgOptionText(message, params.EscapeText),
		slack.MsgOptionPostMessageParameters(slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true}))
}

func DeleteMessage(ev *slack.MessageEvent) {
	api.DeleteMessage(ev.Channel, ev.Timestamp)
}

func StripMailTo(text string) string {
	if strings.Contains(text, ":") && strings.Contains(text, "|") {
		return strings.Split(strings.Split(text, ":")[1], "|")[0]
	} else {
		return text
	}
}

func StripURL(text string) string {
	var t = text

	if strings.Contains(t, "|") {
		t = strings.Split(t, "|")[1]
	}

	if strings.Contains(t, "<") {
		t = strings.Split(t, "<")[1]
	}

	if strings.Contains(t, ">") {
		t = strings.Split(t, ">")[0]
	}

	return t
}

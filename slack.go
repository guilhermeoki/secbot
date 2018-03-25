package main

import (
	"fmt"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"strings"
	"time"
)

func AtBot(message string) bool {
	if strings.Contains(message, fmt.Sprintf("<@%s>", botid)) {
		return true

	}
	return false
}

func GetUser(id string) (*slack.User, error) {
	user, err := api.GetUserInfo(id)

	if err != nil {
		caller, file := GetCaller()
		logger.WithFields(logrus.Fields{
			"prefix": "GetID",
			"caller": caller,
			"file":   file,
			"error":  err.Error(),
		}).Error("An Error Occurred")
	}

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
		if user.Name == name {
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
	if strings.Contains(text, ">") && strings.Contains(text, "|") {
		return strings.Split(strings.Split(text, "|")[1], ">")[0]
	} else {
		return text
	}
}

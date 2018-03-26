package secbot

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

/*
Checks if a message was directed to the bot by checking if it starts with the bot ID.

See: https://godoc.org/github.com/pagarme/secbot/#GetID
*/
func AtBot(message string) bool {
	if strings.HasPrefix(message, fmt.Sprintf("<@%s>", botid)) {
		return true
	}
	return false
}

/*
Gets an slack.Group object by it's ID
*/
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

/*
Gets an slack.Channel object by it's ID
*/
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

/*
Gets an slack.User object by it's ID
*/
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

// Gets the bot ID by looking for a user with a matching username as the one set in botname global variable.
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

/*
This function in called on RTM *slack.ConnectedEvent as a goroutine.

It periodically checks for new channels and joins them.
*/
func JoinChannels(notify bool) {
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

				if notify {
					PostMessage(channel.Name, "Every move you make\nEvery step you take\nI'll be watching you")
				}

			}
		}

		time.Sleep(60 * time.Second)

	}

}

/*
Simple helper function to post a message to a channel.
*/
func PostMessage(channel string, message string) {
	api.PostMessage(channel, message, slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true})

}

/*
Simple helper function to post an epheremal message to an user.
*/
func PostEphemeralMessage(channel string, user string, message string) {
	params := slack.NewPostMessageParameters()

	api.PostEphemeral(channel, user, slack.MsgOptionText(message, params.EscapeText),
		slack.MsgOptionPostMessageParameters(slack.PostMessageParameters{AsUser: true, LinkNames: 1, Markdown: true}))
}

/*
Simple helper function to delete a message.
*/
func DeleteMessage(ev *slack.MessageEvent) {
	api.DeleteMessage(ev.Channel, ev.Timestamp)
}

/*
Simple helper function to remove mailto formatting from an string.
*/
func StripMailTo(text string) string {
	if strings.Contains(text, ":") && strings.Contains(text, "|") {
		return strings.Split(strings.Split(text, ":")[1], "|")[0]
	} else {
		return text
	}
}

/*
Simple helper function to remove url formatting from an string.
*/
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

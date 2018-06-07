package secbot

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
)

func SlackHandlerStart() {

	RegisterHandler("slack")

	AddCommand(Command{
		Regex:       regexp.MustCompile("slack (?P<command>list nomfa)"),
		Help:        "Lista os usuários sem MFA",
		Usage:       "slack list nomfa",
		Handler:     SlackListNoMFACommand,
		HandlerName: "slack"})

	AddCommand(Command{
		Regex:              regexp.MustCompile("slack (?P<command>invite) (?P<email>\\S+)"),
		Help:               "Envia convite para o Slack",
		RequiredPermission: "slack",
		HandlerName:        "slack",
		Usage:              "slack invite <email>",
		Parameters: map[string]string{
			"email": "\\S+",
		},
		Handler: SlackInvate})

	AddCommand(Command{
		Regex:              regexp.MustCompile("slack (?P<command>revoke) (?P<email>\\S+)"),
		Help:               "Exclui o convite do Slack",
		RequiredPermission: "slack",
		HandlerName:        "slack",
		Usage:              "slack revoke <email>",
		Parameters: map[string]string{
			"email": "\\S+",
		},
		Handler: SlackRevoke})

	AddCommand(Command{
		Regex:              regexp.MustCompile("slack (?P<command>delete) (?P<email>\\S+)"),
		Help:               "Exclui o usuario do Slack",
		RequiredPermission: "slack",
		HandlerName:        "slack",
		Usage:              "slack delete <email>",
		Parameters: map[string]string{
			"email": "\\S+",
		},
		Handler: SlackDelete})

	go SlackGetMembers()
}

/*
Lists users without MFA.

HandlerName

 slack

Regex

 slack (?P<command>list nomfa)


Usage

 slack list nomfa
*/
func SlackListNoMFACommand(md map[string]string, ev *slack.MessageEvent) {
	info, _ := api.GetTeamInfo()
	local_nomfa, _ := GetTrackedUsers("slack", info.Name, "nomfa")

	PostMessage(ev.Channel, fmt.Sprintf("@%s Usuários sem MFA: %s", ev.Username, strings.Join(local_nomfa, " ")))

}

func SlackInvate(md map[string]string, ev *slack.MessageEvent) {
	logger.WithFields(logrus.Fields{
		"prefix": "rtm.IncomingEvents",
		"text":   ev.Text,
		"name":   ev.Username,
		"user":   ev.User,
	}).Info("Invite to Slack")
	mail := StripMailTo(ev.Text)
	if invite(mail) == true {
		PostMessage(ev.Channel, fmt.Sprintf("@%s O convite para %s foi enviado com Sucesso", ev.Username, mail))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Erro ao enviar o convite para o email: %s", ev.Username, mail))
	}
}

func SlackRevoke(md map[string]string, ev *slack.MessageEvent) {
	logger.WithFields(logrus.Fields{
		"prefix": "rtm.IncomingEvents",
		"text":   ev.Text,
		"name":   ev.Username,
		"user":   ev.User,
	}).Info("Revoke invite Slack")
	mail := StripMailTo(ev.Text)
	if delInvite(mail) == true {
		PostMessage(ev.Channel, fmt.Sprintf("@%s O convite para %s foi revogado com Sucesso", ev.Username, mail))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Erro ao revogar o convite para o email: %s", ev.Username, mail))
	}
}

func SlackDelete(md map[string]string, ev *slack.MessageEvent) {
	logger.WithFields(logrus.Fields{
		"prefix": "rtm.IncomingEvents",
		"text":   ev.Text,
		"name":   ev.Username,
		"user":   ev.User,
	}).Info("Delete user of Slack")
	mail := StripMailTo(ev.Text)
	if delUser(mail) == true {
		PostMessage(ev.Channel, fmt.Sprintf("@%s O email %s foi removido com Sucesso", ev.Username, mail))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Erro ao remover o email: %s do Slack", ev.Username, mail))
	}
}

/*
Constantly queries Slack API for the same account as the bot's token to track it's users
*/
func SlackGetMembers() {
	info, _ := api.GetTeamInfo()

	for {

		time.Sleep(100 * time.Second)

		users, err := api.GetUsers()

		if err != nil {
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "SlackGetMembers",
				"caller": caller,
				"file":   file,
				"error":  err.Error(),
			}).Error("An Error Occurred")
			continue
		}

		var nomfa []string
		var ownerList []string
		var adminList []string
		var memberList []string

		var local_nomfa []string
		var local_ownerList []string
		var local_adminList []string
		var local_memberList []string

		var added_ownerList []string
		var added_adminList []string
		var added_memberList []string

		var removed_ownerList []string
		var removed_adminList []string
		var removed_memberList []string

		local_nomfa, _ = GetTrackedUsers("slack", info.Name, "nomfa")
		local_ownerList, _ = GetTrackedUsers("slack", info.Name, "owner")
		local_adminList, _ = GetTrackedUsers("slack", info.Name, "admin")
		local_memberList, _ = GetTrackedUsers("slack", info.Name, "member")

		for _, v := range users {
			if !v.Deleted {
				memberList = append(memberList, v.Name)
				if !stringInSlice(v.Name, local_memberList) {
					TrackUser("slack", info.Name, "member", v.Name, "INSERT")
					added_memberList = append(added_memberList, v.Name)

				}

				if !v.Has2FA {
					nomfa = append(nomfa, v.Name)
					if !stringInSlice(v.Name, local_nomfa) {
						TrackUser("slack", info.Name, "nomfa", v.Name, "INSERT")
					}
				}

				if v.IsOwner {
					ownerList = append(ownerList, v.Name)
					if !stringInSlice(v.Name, local_ownerList) {
						TrackUser("slack", info.Name, "owner", v.Name, "INSERT")
						added_ownerList = append(added_ownerList, v.Name)
					}
				}

				if v.IsAdmin {
					adminList = append(adminList, v.Name)
					if !stringInSlice(v.Name, local_adminList) {
						TrackUser("slack", info.Name, "admin", v.Name, "INSERT")
						added_adminList = append(added_adminList, v.Name)
					}
				}
			}

		}

		if len(added_ownerList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] @channel Usuários adicionados como OWNER: %s", strings.Join(added_ownerList, " ")))
		}
		if len(added_adminList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] @here Usuários adicionados como ADMIN: %s", added_adminList))
		}
		if len(added_memberList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] Usuários adicionados como MEMBER: %s", added_memberList))
		}

		for _, v := range local_ownerList {
			if !stringInSlice(v, ownerList) {
				removed_ownerList = append(removed_ownerList, v)
				TrackUser("slack", info.Name, "owner", v, "DELETE")
			}
		}

		for _, v := range local_adminList {
			if !stringInSlice(v, adminList) {
				removed_adminList = append(removed_adminList, v)
				TrackUser("slack", info.Name, "admin", v, "DELETE")
			}
		}

		for _, v := range local_memberList {
			if !stringInSlice(v, memberList) {
				removed_memberList = append(removed_memberList, v)
				TrackUser("slack", info.Name, "member", v, "DELETE")
			}
		}

		for _, v := range local_nomfa {
			if !stringInSlice(v, nomfa) {
				TrackUser("slack", info.Name, "nomfa", v, "DELETE")
			}
		}

		if len(removed_ownerList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] @channel Usuários removidos como OWNER: %s", strings.Join(removed_ownerList, " ")))
		}
		if len(removed_adminList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] @here Usuários removidos como ADMIN: %s", removed_adminList))
		}
		if len(removed_memberList) > 0 {
			PostMessage(logs_channel, fmt.Sprintf("[SLACK] Usuários removidos como MEMBER: %s", removed_memberList))
		}
	}
}

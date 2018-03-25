package main

import (
	"fmt"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"
	"time"
)

func SlackHandlerStart() {

	logger.WithFields(logrus.Fields{
		"handler": "slack",
	}).Info("Starting Handler")

	AddCommand(Command{Regex: regexp.MustCompile("slack (?P<command>list nomfa)"), Help: "Lista os usuários sem MFA", Handler: SlackListNoMFACommand})

	go SlackGetMembers()
}

func SlackListNoMFACommand(md map[string]string, ev *slack.MessageEvent) {
	info, _ := api.GetTeamInfo()
	local_nomfa, _ := GetTrackedUsers("slack", info.Name, "nomfa")

	PostMessage(ev.Channel, fmt.Sprintf("@%s Usuários sem MFA: %s", ev.Username, strings.Join(local_nomfa, " ")))
}

func SlackGetMembers() {
	info, _ := api.GetTeamInfo()

	for {

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
			}
		}

		for _, v := range local_adminList {
			if !stringInSlice(v, adminList) {
				removed_adminList = append(removed_adminList, v)
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

		time.Sleep(60 * time.Second)
	}
}

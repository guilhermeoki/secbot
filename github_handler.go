package main

import (
	"context"
	"fmt"
	"github.com/google/go-github/github"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"regexp"
	"strings"
	"time"
)

func GitHubHandlerStart() {

	logger.WithFields(logrus.Fields{
		"handler": "github",
	}).Info("Starting Handler")

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>list organizations)"),
		Help: "Lista as organizações cadastradas", Handler: GitHubListOrganizationsCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>list members)"),
		Help: "Lista os membros da organização", Handler: GitHubListMembersCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>list owners)"),
		Help: "Lista os donos da organização", Handler: GitHubListOwnersCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>list nomfa)"),
		Help: "Lista os membros da organização sem MFA", Handler: GitHubListNoMFACommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<organization>\\S+) (?P<command>list members)"),
		Help: "Lista os membros da organização <organization>", Handler: GitHubListMembersCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<organization>\\S+) (?P<command>list owners)"),
		Help: "Lista os donos da organização <organization>", Handler: GitHubListOwnersCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<organization>\\S+) (?P<command>list nomfa)"),
		Help: "Lista os membros da organização <organization> sem MFA", Handler: GitHubListNoMFACommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>invite user) (?P<users>.*)"),
		Help: "Convida usuários para a organização", Handler: GitHubInviteUserCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<organization>\\S+) (?P<command>invite user) (?P<users>.*)"),
		Help: "Convida usuários para a organização <organization>", Handler: GitHubInviteUserCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>set default organization) (?P<organization>\\S+)"),
		Help: "Define a organização padrão do GitHub", Handler: GitHubSetDefaultOrganizationCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>set organization) (?P<organization>\\S+) (?P<token>\\S+)"),
		Help: "Seta a organização <organization> com os dados informados", Handler: GitHubSetOrganizationCommand})

	AddCommand(Command{Regex: regexp.MustCompile("github (?P<command>set organization) (?P<organization>\\S+) (?P<login>\\S+) (?P<password>\\S+)"),
		Help: "Seta a organização <organization> com os dados informados", Handler: GitHubSetOrganizationCommand})

	go GitHubGetMembers()
}

func GitHubHasOrganization(organization string) bool {
	creds, err := GitHubListOrganizations()

	if err != nil {
		return false
	}

	if creds == nil {
		return false
	} else {
		if stringInSlice(organization, creds) {
			return true
		}
	}

	return false
}

func GitHubInviteUserCommand(md map[string]string, ev *slack.MessageEvent) {
	if !IsAuthorized("github", ev.Username) {
		Unauthorized(md, ev)
		return
	}
	
	avalid, organization := GitHubValidateOrganization(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma organização especificada e aplicação padrão não configurada\n"+
			"Utilize `github set default organization <organization>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !GitHubHasOrganization(organization) {
		creds, _ := GitHubListOrganizations()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, organization, strings.Join(creds, "\n")))
		return
	}

	client, ctx, _ := GitHubGetClient(organization)

	org, _, _ := client.Organizations.Get(ctx, organization)

	var invited []string

	var failed []GenericError

	for _, u := range strings.Split(md["users"], " ") {
		var user = StripMailTo(u)
		var role = "member"

		guser, _, err := client.Users.Get(ctx, user)

		if err != nil {
			failed = append(failed, GenericError{Key: user,
				Error: fmt.Sprintf("Ocorreu um erro obtendo o usuário: %s",
					err.Error())})
			continue
		}

		var membership = github.Membership{
			Role:         &role,
			Organization: org,
			User:         guser,
		}

		_, _, err = client.Organizations.EditOrgMembership(ctx, user, organization, &membership)

		if err != nil {
			failed = append(failed, GenericError{Key: user,
				Error: fmt.Sprintf("Ocorreu um erro convidando o usuário: %s",
					err.Error())})
			continue
		} else {
			invited = append(invited, user)
		}
	}

	var msg = fmt.Sprintf("@%s *### Resultado ###*\n", ev.Username)

	if len(invited) > 0 {
		msg += fmt.Sprintf("*Usuários Convidados*\n%s", strings.Join(invited, " "))
	}
	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	}

	PostMessage(ev.Channel, msg)

}

func GitHubSetDefaultOrganizationCommand(md map[string]string, ev *slack.MessageEvent) {
	if !IsAuthorized("github", ev.Username) {
		Unauthorized(md, ev)
		return
	}

	creds, _ := GitHubListOrganizations()

	if !GitHubHasOrganization(md["organization"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["organization"], strings.Join(creds, "\n")))
		return
	}

	SetHandlerConfig("github", "default_organization", md["organization"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Organização padrão setada para `%s`",
		ev.Username, md["organization"]))
}

func GitHubValidateOrganization(md map[string]string) (bool, string) {
	var organization = ""

	if val, ok := md["organization"]; ok {
		organization = val
	} else {
		organization, _ = GetHandlerConfig("github", "default_organization")
	}

	if len(organization) == 0 {
		return false, organization
	}

	return true, organization
}

func GitHubListMembersCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, organization := GitHubValidateOrganization(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma organização especificada e aplicação padrão não configurada\n"+
			"Utilize `github set default organization <organization>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !GitHubHasOrganization(organization) {
		creds, _ := GitHubListOrganizations()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, organization, strings.Join(creds, "\n")))
		return
	}

	local_member, _ := GetTrackedUsers("github", organization, "member")

	PostMessage(ev.Channel, fmt.Sprintf("@%s Membros: %s", ev.Username, strings.Join(local_member, " ")))
}

func GitHubListOwnersCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, organization := GitHubValidateOrganization(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma organização especificada e aplicação padrão não configurada\n"+
			"Utilize `github set default organization <organization>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !GitHubHasOrganization(organization) {
		creds, _ := GitHubListOrganizations()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, organization, strings.Join(creds, "\n")))
		return
	}

	local_owner, _ := GetTrackedUsers("github", organization, "owner")

	PostMessage(ev.Channel, fmt.Sprintf("@%s Owners: %s", ev.Username, strings.Join(local_owner, " ")))
}

func GitHubListNoMFACommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, organization := GitHubValidateOrganization(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma organização especificada e aplicação padrão não configurada\n"+
			"Utilize `github set default organization <organization>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	if !GitHubHasOrganization(organization) {
		creds, _ := GitHubListOrganizations()
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, organization, strings.Join(creds, "\n")))
		return
	}

	local_nomfa, _ := GetTrackedUsers("github", organization, "nomfa")

	PostMessage(ev.Channel, fmt.Sprintf("@%s Usuários sem MFA: %s", ev.Username, strings.Join(local_nomfa, " ")))
}

func GitHubListOrganizationsCommand(md map[string]string, ev *slack.MessageEvent) {
	ncreds := GitHubGetOrganizationsWithDefault()

	if ncreds == nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhuma organização cadastrada",
			ev.Username))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de organizações cadastradas ###*\n%s",
			ev.Username, strings.Join(ncreds, "\n")))
	}
}

func GitHubGetCredentials(organization string) (ExternalCredential, error) {
	cred, err := CredentialsGetCredential("github", organization)

	return cred, err
}

func GitHubGetClient(organization string) (*github.Client, context.Context, error) {
	ctx := context.Background()

	cred, err := GitHubGetCredentials(organization)

	if err != nil {
		return nil, ctx, err
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cred.Login},
	)

	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	return client, ctx, nil
}

func GitHubListOrganizations() ([]string, error) {
	creds, err := CredentialsListCredentials("github")

	if err != nil {
		return nil, err
	}

	if len(creds) > 0 {
		var organizations []string

		for _, v := range creds {
			organizations = append(organizations, v.Name)

		}

		return organizations, nil
	} else {
		return nil, nil
	}

}

func GitHubGetOrganizationsWithDefault() []string {
	organizations, _ := GitHubListOrganizations()

	var norganizations []string

	var def = GitHubGetDefaultOrganization()
	for _, v := range organizations {
		if v == def {
			norganizations = append(norganizations, fmt.Sprintf("*%s* [default]", v))
		} else {
			norganizations = append(norganizations, v)
		}
	}

	return norganizations
}

func GitHubGetDefaultOrganization() string {

	organization, _ := GetHandlerConfig("github", "default_organization")

	if len(organization) == 0 {
		return ""
	}

	return organization

}

func GitHubSetOrganizationCommand(md map[string]string, ev *slack.MessageEvent) {

	DeleteMessage(ev)

	if !IsAuthorized("github", ev.Username) {
		Unauthorized(md, ev)
		return
	}

	var ex ExternalCredential

	ex.Module = "github"
	ex.Name = md["organization"]

	if _, ok := md["token"]; ok {
		ex.Login = md["token"]
	} else {
		ex.Login = md["login"]
		ex.Password = md["password"]
	}

	err := CredentialsSetCredential(ex)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro cadastrando a organização `%s`: %s",
			ev.Username, md["organization"], err.Error()))
	} else {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Organização `%s` cadastrada com sucesso",
			ev.Username, md["organization"]))
	}

}

func GitHubGetMembers() {

	for {

		organizations, _ := GitHubListOrganizations()

		for _, org := range organizations {
			client, ctx, _ := GitHubGetClient(org)

			membersfilter := github.ListMembersOptions{
				PublicOnly:  false,
				Role:        "member",
				ListOptions: github.ListOptions{},
			}

			ownersfilter := github.ListMembersOptions{
				PublicOnly:  false,
				Role:        "admin",
				ListOptions: github.ListOptions{},
			}

			nomfafilter := github.ListMembersOptions{
				PublicOnly:  false,
				Filter:      "2fa_disabled",
				ListOptions: github.ListOptions{},
			}

			rusers, _, err := client.Organizations.ListMembers(ctx, org, &membersfilter)

			if err != nil {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix": "GitHubGetMembers",
					"caller": caller,
					"file":   file,
					"error":  err.Error(),
				}).Error("An Error Occurred")
				continue
			}

			rowners, _, err := client.Organizations.ListMembers(ctx, org, &ownersfilter)

			if err != nil {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix": "GitHubGetMembers",
					"caller": caller,
					"file":   file,
					"error":  err.Error(),
				}).Error("An Error Occurred")
				continue
			}

			rnomfa, _, err := client.Organizations.ListMembers(ctx, org, &nomfafilter)

			if err != nil {
				caller, file := GetCaller()
				logger.WithFields(logrus.Fields{
					"prefix": "GitHubGetMembers",
					"caller": caller,
					"file":   file,
					"error":  err.Error(),
				}).Error("An Error Occurred")
				continue
			}

			var nomfa []string
			var ownerList []string
			var memberList []string

			var local_nomfa []string
			var local_ownerList []string
			var local_memberList []string

			var added_ownerList []string
			var added_memberList []string

			var removed_ownerList []string
			var removed_memberList []string

			local_nomfa, _ = GetTrackedUsers("github", org, "nomfa")
			local_ownerList, _ = GetTrackedUsers("github", org, "owner")
			local_memberList, _ = GetTrackedUsers("github", org, "member")

			for _, v := range rusers {

				memberList = append(memberList, *v.Login)
				if !stringInSlice(*v.Login, local_memberList) {
					TrackUser("github", org, "member", *v.Login, "INSERT")
					added_memberList = append(added_memberList, *v.Login)

				}
			}

			for _, v := range rowners {

				ownerList = append(ownerList, *v.Login)
				if !stringInSlice(*v.Login, local_ownerList) {
					TrackUser("github", org, "owner", *v.Login, "INSERT")
					added_ownerList = append(added_ownerList, *v.Login)

				}
			}

			for _, v := range rnomfa {

				nomfa = append(nomfa, *v.Login)
				if !stringInSlice(*v.Login, local_nomfa) {
					TrackUser("github", org, "nomfa", *v.Login, "INSERT")

				}
			}

			if len(added_ownerList) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[GITHUB] @here Usuários adicionados como OWNER: %s", strings.Join(added_ownerList, " ")))
			}
			if len(added_memberList) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[GITHUB] Usuários adicionados como MEMBER: %s", added_memberList))
			}

			for _, v := range local_ownerList {
				if !stringInSlice(v, ownerList) {
					removed_ownerList = append(removed_ownerList, v)
				}
			}

			for _, v := range local_memberList {
				if !stringInSlice(v, memberList) {
					removed_memberList = append(removed_memberList, v)
					TrackUser("github", org, "member", v, "DELETE")
				}
			}

			for _, v := range local_nomfa {
				if !stringInSlice(v, nomfa) {
					TrackUser("github", org, "nomfa", v, "DELETE")
				}
			}

			if len(removed_ownerList) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[GITHUB] @here Usuários removidos como OWNER: %s", strings.Join(removed_ownerList, " ")))
			}
			if len(removed_memberList) > 0 {
				PostMessage(logs_channel, fmt.Sprintf("[GITHUB] Usuários removidos como MEMBER: %s", removed_memberList))
			}
		}
		time.Sleep(30 * time.Second)
	}
}

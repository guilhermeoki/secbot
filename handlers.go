package main

import (
	"github.com/nlopes/slack"
	"regexp"
	"fmt"
	"github.com/sirupsen/logrus"
	"reflect"
)

type Command struct {
	Regex              *regexp.Regexp
	Help               string
	Usage              string
	RequiredPermission string
	HandlerName        string
	Handler            func(md map[string]string, ev *slack.MessageEvent)
	Parameters         map[string]string
}

var commands []Command

type Interceptor struct {
	Regex    *regexp.Regexp
	Handler  func(md map[string]string, ev *slack.MessageEvent)
	Continue bool
}

var interceptors []Interceptor

type GenericError struct {
	Key   string
	Error string
}

var handlers []string

func RegisterHandler(handler string) {
	AddCommand(Command{
		Regex:              regexp.MustCompile(fmt.Sprintf("(?P<handler>%s) help", handler)),
		Help:               fmt.Sprintf("Obtém ajuda para o módulo `%s`", handler),
		Usage:              fmt.Sprintf("%s help", handler),
		Handler:            GenerateHandlerHelp,
		HandlerName:        handler,
		RequiredPermission: "help"})

	handlers = append(handlers, handler)

	logger.WithFields(logrus.Fields{
		"handler": handler,
	}).Info("Starting Handler")

}

func GenerateHandlerHelp(md map[string]string, ev *slack.MessageEvent) {

	if !stringInSlice(md["handler"], handlers) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Módulo `%s` não encontado", ev.Username, md["handler"]))
		return
	}

	clist := ListHandlerCommands(md["handler"])

	var attachments []slack.Attachment

	for _, c := range clist {
		var fields []slack.AttachmentField

		keys := reflect.ValueOf(c.Parameters).MapKeys()

		for _, v := range keys {
			f := slack.AttachmentField{
				Title: fmt.Sprintf("%s format", v.String()),
				Value: fmt.Sprintf("`%s`", c.Parameters[v.String()]),
				Short: false,
			}

			fields = append(fields, f)
		}

		a := slack.Attachment{
			Color:         "",
			Fallback:      "",
			CallbackID:    "",
			ID:            0,
			AuthorName:    c.Usage,
			AuthorSubname: "",
			AuthorLink:    "",
			AuthorIcon:    "",
			Title:         "",
			TitleLink:     "",
			Pretext:       "",
			Text:          c.Help,
			ImageURL:      "",
			ThumbURL:      "",
			Fields:        fields,
			Actions:       nil,
			MarkdownIn:    nil,
			Footer:        "",
			FooterIcon:    "",
			Ts:            "",
		}

		attachments = append(attachments, a)
	}

	if len(attachments) == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhum comando encontrado para o módulo `%s`", ev.Username, md["handler"]))
		return
	}

	params := slack.PostMessageParameters{Attachments: attachments, AsUser: true}

	api.PostMessage(ev.Channel, fmt.Sprintf("@%s Ajuda para o módulo `%s`", ev.Username, md["handler"]), params)
}

func ListHandlerCommands(handler string) []Command {
	var clist []Command

	for _, h := range commands {
		fmt.Println(h)
		if h.HandlerName == handler {
			clist = append(clist, h)
		}
	}

	return clist
}

func AddCommand(command Command) {
	commands = append(commands, command)
}

func AddInterceptor(interceptor Interceptor) {
	interceptors = append(interceptors, interceptor)
}

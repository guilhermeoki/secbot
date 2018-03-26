package main

import (
	"fmt"
	"github.com/nlopes/slack"
	"regexp"
)

type Command struct {
	Regex   *regexp.Regexp
	Help    string
	Handler func(md map[string]string, ev *slack.MessageEvent)
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

func AddCommand(command Command) {
	commands = append(commands, command)
}

func AddInterceptor(interceptor Interceptor) {
	interceptors = append(interceptors, interceptor)
}

func Unauthorized(md map[string]string, ev *slack.MessageEvent) {
	PostMessage(ev.Channel, fmt.Sprintf("@%s Você não está autorizado a executar o comando `%s`. "+
		"Esse incidente foi logado.", ev.Username, md["command"]))
}

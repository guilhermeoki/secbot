package secbot

import (
	"fmt"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"reflect"
	"regexp"
)

var unknown_command_phrases []string

/*
Defines a command, which should then be registered with AddCommand().

For every message received by the RTM, the commands regexes are analysed until the first one matches,
at which point the Handler() function is called and the loop breaks.

The Help, Usage and Parameters fields are used for generating the help messages with GenerateHandlerHelp().

It's important to call RegisterHandler("handlername") and use the same name for the HandlerName field,
as the help depends on that.

The RequiredPermission field is used both by GenerateHandlerHelp() and by IsAuthorized()
command to check if the user is allowed to perform that command.

See: https://godoc.org/github.com/pagarme/secbot/#RegisterHandler

See: https://godoc.org/github.com/pagarme/secbot/#AddCommand

See: https://godoc.org/github.com/pagarme/secbot/#IsAuthorized
*/
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

/*
Defines an interceptor listener, which should then be registered with AddInterceptor().

For every message received by the RTM, the interceptor regexes are analysed until one matches,
at which point the Handler() function is called. The loop will break if Continue is false, otherwise it will go on.

Continue must be false for the CreditCardFoundInterceptor(), otherwise PANs may be logged, which is against PCI DSS rules.

See: https://godoc.org/github.com/pagarme/secbot/#RegisterInterceptor

See: https://godoc.org/github.com/pagarme/secbot/#AddInterceptor
*/
type Interceptor struct {
	Regex    *regexp.Regexp
	Handler  func(md map[string]string, ev *slack.MessageEvent)
	Continue bool
}

var interceptors []Interceptor

/*
Defines an error.

Useful when multiple operations derive from the same command, as errors can then be reported individually.

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

	if len(failed) > 0 {
		msg += fmt.Sprintf("*Erros*\n")
		for _, v := range failed {
			msg += fmt.Sprintf("%s - `%s`\n", v.Key, v.Error)
		}
	}

*/
type GenericError struct {
	Key   string
	Error string
}

var handlers []string

/*
Registers an handler, generating it's help command by calling AddCommand with a specially crafted command whose regex
is simply "<handler> help" and handler is GenerateHandlerHelp().

The handler is also added to the handles array and a log message is generated.

This function should be called by the HandlerHandlerStart() function,
which in turn should be called by the StartHandlers() function.

See: https://godoc.org/github.com/pagarme/secbot/#GenerateHandlerHelp

See: https://godoc.org/github.com/pagarme/secbot/#AddCommand

See: https://godoc.org/github.com/pagarme/secbot/#StartHandlers
*/
func RegisterHandler(handler string) {
	AddCommand(Command{
		Regex:       regexp.MustCompile(fmt.Sprintf("(?P<handler>%s) help", handler)),
		Help:        fmt.Sprintf("Obtém ajuda para o módulo `%s`", handler),
		Usage:       fmt.Sprintf("%s help", handler),
		Handler:     GenerateHandlerHelp,
		HandlerName: handler})

	handlers = append(handlers, handler)

	logger.WithFields(logrus.Fields{
		"handler": handler,
	}).Info("Starting Handler")

}

/*
Registers an interceptor.

Currently this only logs a message stating the the interceptor was started.
*/
func RegisterInterceptor(interceptor string) {

	logger.WithFields(logrus.Fields{
		"interceptor": interceptor,
	}).Info("Starting Interceptor")

}

/*
Generates the help message for the specified handler.

Message is generated based of the commands added by AddCommand() whose HandlerName is the same as the md["handler"].

This function is called when "<handler> help" is issued, and RegisterHandler()
is responsible for registering the required regex for that to work.

See: https://godoc.org/github.com/pagarme/secbot/#RegisterHandler

See: https://godoc.org/github.com/pagarme/secbot/#AddCommand
*/
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

		if len(c.RequiredPermission) > 0 {
			f := slack.AttachmentField{Title: "Required Permission", Value: c.RequiredPermission, Short: false}

			fields = append(fields, f)
		}

		for _, v := range keys {
			f := slack.AttachmentField{
				Title: fmt.Sprintf("%s format", v.String()),
				Value: fmt.Sprintf("`%s`", c.Parameters[v.String()]),
				Short: true,
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

/*
Lists all commands registered to an specific handler.

This function is used by GenerateHandlerHelp().

See: https://godoc.org/github.com/pagarme/secbot/#RegisterHandler

See: https://godoc.org/github.com/pagarme/secbot/#AddCommand

See: https://godoc.org/github.com/pagarme/secbot/#GenerateHandlerHelp
*/
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

/*
Adds a command by simply appending it to the commands array.

Those commands are checked at every RTM message for regex match, and also are used by the ListHandlerCommands() function.

See: https://godoc.org/github.com/pagarme/secbot/#Command

See: https://godoc.org/github.com/pagarme/secbot/#RegisterHandler

See: https://godoc.org/github.com/pagarme/secbot/#ListHandlerCommands
*/
func AddCommand(command Command) {
	commands = append(commands, command)
}

func AddInterceptor(interceptor Interceptor) {
	interceptors = append(interceptors, interceptor)
}

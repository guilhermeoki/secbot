package secbot

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/nlopes/slack"
)

func UpdateHandlerStart() {

	RegisterHandler("update")

	AddCommand(Command{
		Regex:              regexp.MustCompile("update (?P<command>secbot)"),
		Help:               "Atualiza o Secbot com a última versão no GitHub",
		RequiredPermission: "update",
		HandlerName:        "update",
		Usage:              "update secbot",
		Handler:            updatesecbot})
}

func updatesecbot(md map[string]string, ev *slack.MessageEvent) {
	file := os.Getenv("GOPATH") + "/src/github.com/pagarme/secbot/deploy_secbot.sh"
	PostMessage(ev.Channel, fmt.Sprintf("@%s Secbot está se atualizando com o arquivo: %s", ev.Username, file))
	exec.Command("/bin/chmod", "+x", file).Output()
	exec.Command("sudo", file).Output()
}

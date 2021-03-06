package secbot

import (
	"regexp"
	"strings"

	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
)

func CreditCardInterceptorStart() {

	RegisterInterceptor("credit_card")

	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"4[0-9]{12}(?:[0-9]{3})?"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"3[47][0-9]{13}"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"3(?:0[0-5]|[68][0-9])[0-9]{11}"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"6(?:011|5[0-9]{2})[0-9]{12}"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"(?:2131|1800|35\\d{3})\\d{11}"), Handler: CreditCardFoundInterceptor, Continue: false})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"\\|[0-9]{4}-[0-9]{4}-[0-9]{4}>-[0-9]{4}"), Handler: CreditCardFoundInterceptor, Continue: false})

}

/*
If a credit card is found, delete the message and warn the user it's against PCI rules.
*/
func CreditCardFoundInterceptor(md map[string]string, ev *slack.MessageEvent) {
	var user_ver = ""
	var user_text = ""
	err := ev.SubMessage
	if err == nil {
		user_ver = ev.User
		user_text = ev.Text
	} else {
		user_ver = ev.SubMessage.User
		user_text = ev.SubMessage.Text
	}
	compRegex := []string{"https://", "http://"}
	for _, cont := range compRegex {
		if strings.ContainsAny(cont, user_text) {
			return
		}
	}
	if user_ver != botid {
		DeleteMessage(ev)

		logger.WithFields(logrus.Fields{
			"prefix":   "main",
			"channel":  ev.Channel,
			"user":     user_ver,
			"username": ev.Username,
		}).Info("Card Detected")

		PostEphemeralMessage(ev.Channel, user_ver, "O PCI determina que dados sensíveis de cartão (PAN e CVV) "+
			"não devem ser compartilhados em mídias como "+
			"email, SMS, Slack, Telegram, Whatsapp e outros IMs. Por favor, respeite essa regra.")
	}
}

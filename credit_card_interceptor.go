package main

import (
	_ "github.com/mattn/go-sqlite3"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"regexp"
)

func CreditCardInterceptorStart() {

	logger.WithFields(logrus.Fields{
		"handler": "credit_card",
	}).Info("Starting Interceptor")

	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"4[0-9]{12}(?:[0-9]{3})?"), Handler: CreditCardFoundInterceptor})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}"), Handler: CreditCardFoundInterceptor})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"3[47][0-9]{13}"), Handler: CreditCardFoundInterceptor})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"3(?:0[0-5]|[68][0-9])[0-9]{11}"), Handler: CreditCardFoundInterceptor})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"6(?:011|5[0-9]{2})[0-9]{12}"), Handler: CreditCardFoundInterceptor})
	AddInterceptor(Interceptor{Regex: regexp.MustCompile(
		"(?:2131|1800|35\\d{3})\\d{11}"), Handler: CreditCardFoundInterceptor})

}

func CreditCardFoundInterceptor(md map[string]string, ev *slack.MessageEvent) {
	DeleteMessage(ev)

	logger.WithFields(logrus.Fields{
		"prefix":   "main",
		"channel":  ev.Channel,
		"user":     ev.User,
		"username": ev.Username,
	}).Info("Card Detected")

	PostEphemeralMessage(ev.Channel, ev.User, "O PCI determina que dados sensíveis de cartão (PAN e CVV) "+
		"não devem ser compartilhados em mídias como "+
		"email, SMS, Slack, Telegram, Whatsapp e outros IMs. Por favor, respeite essa regra.")
}

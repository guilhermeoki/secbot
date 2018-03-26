package secbot

import (
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/nlopes/slack"
	"regexp"
	"strings"
)

func WAFHandlerStart() {

	RegisterHandler("waf")

	AddCommand(Command{
		Regex:       regexp.MustCompile("waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>list)"),
		Help:        "Lista os IPs bloqueados no WAF para a conta <account> região <region>",
		Usage:       "waf <account> <region> list",
		Handler:     WAFListCommand,
		HandlerName: "waf",
		Parameters: map[string]string{
			"account": "\\S+",
			"region":  "\\S+",
		}})

	AddCommand(Command{
		Regex:       regexp.MustCompile("waf (?P<command>list)"),
		Help:        "Lista os IPs bloqueados no WAF",
		Usage:       "waf list",
		Handler:     WAFListCommand,
		HandlerName: "waf"})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Bloqueia IPs no WAF",
		Usage:              "waf block <addresses>",
		Handler:            WAFBlockCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Desbloqueia IPs no WAF",
		Usage:              "waf unblock <addresses>",
		Handler:            WAFUnblockCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Bloqueia IPs no WAF para a conta <account> região <region>",
		Usage:              "waf <account> <region> block <addresses>",
		Handler:            WAFBlockCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"account":   "\\S+",
			"region":    "\\S+",
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)"),
		Help:               "Desbloqueia IPs no WAF para a conta <account> região <region>",
		Usage:              "waf <account> <region> unblock <addresses>",
		Handler:            WAFUnblockCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"account":   "\\S+",
			"region":    "\\S+",
			"addresses": "(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<command>set default account) (?P<account>\\S+)"),
		Help:               "Define a conta padrão do WAF",
		Usage:              "waf set default account <account>",
		Handler:            WAFSetDefaultAccountCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"account": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<command>set default region) (?P<region>\\S+)"),
		Help:               "Define a região padrão do WAF",
		Usage:              "waf set default region <region>",
		Handler:            WAFSetDefaultRegionCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"region": "\\S+",
		}})

	AddCommand(Command{
		Regex:              regexp.MustCompile("waf (?P<command>set default ipset) (?P<ipset>.*)"),
		Help:               "Define a região padrão do WAF",
		Usage:              "waf set default ipset <ipset>",
		Handler:            WAFSetDefaultIPSetCommand,
		RequiredPermission: "waf",
		HandlerName:        "waf",
		Parameters: map[string]string{
			"ipset": ".*",
		}})

}

func WAFGetProfilesWithDefault() []string {
	profiles := AWSListProfiles()

	var nprofiles []string

	var def = WAFGetDefaultProfile()
	for _, v := range profiles {
		if v == def {
			nprofiles = append(nprofiles, fmt.Sprintf("*%s* [default]", v))
		} else {
			nprofiles = append(nprofiles, v)
		}
	}

	return nprofiles
}

func WAFGetDefaultProfile() string {

	ipset, _ := GetHandlerConfig("waf", "default_profile")

	if len(ipset) == 0 {
		return ""
	}

	return ipset

}

/*
Sets the default account.

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>set default account) (?P<account>\\S+)"

Usage

 waf set default account <account>
*/
func WAFSetDefaultAccountCommand(md map[string]string, ev *slack.MessageEvent) {

	if !AWSHasProfile(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(WAFGetProfilesWithDefault(), "\n")))
		return
	}

	SetHandlerConfig("waf", "default_account", md["account"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Conta padrão setada para `%s`",
		ev.Username, md["account"]))

}

/*
Sets the default region.

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>set default region) (?P<region>\\S+)"

Usage

 waf set default region <region>
*/
func WAFSetDefaultRegionCommand(md map[string]string, ev *slack.MessageEvent) {

	if !AWSHasRegion(md["region"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Região `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["region"], strings.Join(AWSListRegions(), "\n")))
		return
	}

	SetHandlerConfig("waf", "default_region", md["region"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Região padrão setada para `%s`",
		ev.Username, md["region"]))

}

/*
Sets the default IPSet.

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>set default ipset) (?P<ipset>\\S+)"

Usage

 waf set default ipset <ipset>
*/
func WAFSetDefaultIPSetCommand(md map[string]string, ev *slack.MessageEvent) {

	SetHandlerConfig("waf", "default_ipset", md["ipset"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s IPSet padrão setada para `%s`",
		ev.Username, md["ipset"]))

}

func WAFValidateAccount(md map[string]string) (bool, string) {
	var account = ""

	if val, ok := md["account"]; ok {
		account = val
	} else {
		account, _ = GetHandlerConfig("waf", "default_account")
	}

	if len(account) == 0 {
		return false, account
	}

	return true, account
}

func WAFValidateRegion(md map[string]string) (bool, string) {
	var region = ""

	if val, ok := md["region"]; ok {
		region = val
	} else {
		region, _ = GetHandlerConfig("waf", "default_region")
	}

	if len(region) == 0 {
		return false, region
	}

	return true, region
}

/*
Unblocks the specified IPs on the account's WAF

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

 waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>unblock) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

Usage

 waf unblock <addresses>

 waf <account> <region> unblock <addresses>
*/
func WAFUnblockCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := WAFValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e conta padrão não configurada\n"+
			"Utilize `waf set default acccount <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	rvalid, region := WAFValidateRegion(md)

	if !rvalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma região especificada e região padrão não configurada\n"+
			"Utilize `waf set default region <region>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	sess, _ := AWSGetSession(account, region)

	wafr := wafregional.New(sess)

	ipset, _ := WAFGetIPSetByName(wafr, WAFGetDefaultIPSet())

	ips := WAFListIPSetIPs(ipset)

	var tounblock []*waf.IPSetUpdate

	for _, v := range strings.Split(md["addresses"], " ") {
		if stringInSlice(v, ips) {

			var ip = v

			var action = waf.ChangeActionDelete
			var dtype = waf.IPSetDescriptorTypeIpv4

			tounblock = append(tounblock, &waf.IPSetUpdate{Action: &action, IPSetDescriptor: &waf.IPSetDescriptor{Type: &dtype, Value: &ip}})
		}
	}

	if len(tounblock) == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Nenhum dos IPs listados se encontram bloqueado", ev.Username))
		return
	}

	token, err := WAFGetToken(wafr)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro obtendo o token: %s", ev.Username, err.Error()))
		return
	}

	updateinput := waf.UpdateIPSetInput{
		ChangeToken: &token,
		IPSetId:     ipset.IPSet.IPSetId,
		Updates:     tounblock,
	}

	_, err = wafr.UpdateIPSet(&updateinput)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro atualizando o IPSet: %s", ev.Username, err.Error()))
		return
	}

	var updated []string

	for _, v := range tounblock {
		updated = append(updated, *v.IPSetDescriptor.Value)
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs estavam listados e foram desbloqueados: %s", ev.Username, strings.Join(updated, " ")))
}

/*
Blocks the specified IPs on the account's WAF

HandlerName

 waf

RequiredPermission

 waf

Regex

 waf (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

 waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>block) (?P<addresses>(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}\\s?)+)

Usage

 waf block <addresses>

 waf <account> <region> block <addresses>
*/
func WAFBlockCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := WAFValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e conta padrão não configurada\n"+
			"Utilize `waf set default acccount <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	rvalid, region := WAFValidateRegion(md)

	if !rvalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma região especificada e região padrão não configurada\n"+
			"Utilize `waf set default region <region>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	sess, _ := AWSGetSession(account, region)

	wafr := wafregional.New(sess)

	ipset, _ := WAFGetIPSetByName(wafr, WAFGetDefaultIPSet())

	ips := WAFListIPSetIPs(ipset)

	var toblock []*waf.IPSetUpdate

	fmt.Println(md["addresses"])

	for _, v := range strings.Split(md["addresses"], " ") {
		if !stringInSlice(v, ips) {

			var ip = v

			var action = waf.ChangeActionInsert
			var dtype = waf.IPSetDescriptorTypeIpv4

			toblock = append(toblock, &waf.IPSetUpdate{Action: &action, IPSetDescriptor: &waf.IPSetDescriptor{Type: &dtype, Value: &ip}})
		}
	}

	fmt.Println(toblock)

	if len(toblock) == 0 {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Todos os IPs listados já se encontram bloqueados", ev.Username))
		return
	}

	token, err := WAFGetToken(wafr)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro obtendo o token: %s", ev.Username, err.Error()))
		return
	}

	updateinput := waf.UpdateIPSetInput{
		ChangeToken: &token,
		IPSetId:     ipset.IPSet.IPSetId,
		Updates:     toblock,
	}

	_, err = wafr.UpdateIPSet(&updateinput)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro atualizando o IPSet: %s", ev.Username, err.Error()))
		return
	}

	var updated []string

	for _, v := range toblock {
		updated = append(updated, *v.IPSetDescriptor.Value)
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s Os seguintes IPs não estavam listados e foram bloqueados: %s", ev.Username, strings.Join(updated, " ")))
}

func WAFGetToken(wafregional *wafregional.WAFRegional) (string, error) {
	token, err := wafregional.GetChangeToken(&waf.GetChangeTokenInput{})

	return *token.ChangeToken, err
}

/*
Lists blocked IPs.

HandlerName

 waf

Regex

 waf (?P<account>\\S+) (?P<region>\\S+) (?P<command>list)

 waf (?P<command>list)

Usage

 waf <account> <region> list

 waf list
*/

func WAFListCommand(md map[string]string, ev *slack.MessageEvent) {

	avalid, account := WAFValidateAccount(md)

	if !avalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma conta especificada e conta padrão não configurada\n"+
			"Utilize `waf set default acccount <account>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	rvalid, region := WAFValidateRegion(md)

	if !rvalid {
		PostMessage(ev.Channel, fmt.Sprintf("@%s nenhuma região especificada e região padrão não configurada\n"+
			"Utilize `waf set default region <region>` "+
			"ou invoque novamente o comando especificando a conta", ev.Username))
		return
	}

	sess, _ := AWSGetSession(account, region)

	wafr := wafregional.New(sess)

	ips, err := WAFListIPs(wafr)

	if err != nil {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Ocorreu um erro listando os IPs: %s", ev.Username, err.Error()))
		return
	}

	PostMessage(ev.Channel, fmt.Sprintf("@%s *### Lista de IPs bloqueados na conta `%s` região `%s` ###*\n%s",
		ev.Username, account, region, strings.Join(ips, "\n")))

}

func WAFGetIPSetByName(wafregional *wafregional.WAFRegional, name string) (*waf.GetIPSetOutput, error) {
	ipsetlist, err := WAFGetIPSetList(wafregional)

	if err != nil {
		return nil, err
	}

	var ipsetid = ""

	for _, v := range ipsetlist.IPSets {
		if *v.Name == name {
			ipsetid = *v.IPSetId
		}
	}

	if len(ipsetid) == 0 {
		return nil, errors.New(fmt.Sprintf("IPSet %s não encontrado", name))
	}

	ipsetres, err := wafregional.GetIPSet(&waf.GetIPSetInput{
		IPSetId: &ipsetid,
	})

	if err != nil {
		return nil, err
	}

	return ipsetres, nil
}

func WAFGetIPSet(wafregional *wafregional.WAFRegional, ipsetId string) (*waf.GetIPSetOutput, error) {
	ipsetres, err := wafregional.GetIPSet(&waf.GetIPSetInput{
		IPSetId: &ipsetId,
	})

	if err != nil {
		return nil, err
	}

	return ipsetres, nil
}

func WAFListIPSetIPs(ipsetres *waf.GetIPSetOutput) []string {
	descriptors := ipsetres.IPSet.IPSetDescriptors

	var ips []string

	for _, v := range descriptors {
		ips = append(ips, *v.Value)
	}

	return ips
}

func WAFGetDefaultIPSet() string {

	ipset, _ := GetHandlerConfig("waf", "default_ipset")

	if len(ipset) == 0 {
		return ""
	}

	return ipset

}

func WAFGetIPSetList(wafregional *wafregional.WAFRegional) (*waf.ListIPSetsOutput, error) {
	ipsets, err := wafregional.ListIPSets(&waf.ListIPSetsInput{})

	if err != nil {
		return nil, err
	}

	return ipsets, nil
}

func WAFListIPs(wafregional *wafregional.WAFRegional) ([]string, error) {
	ipsetname := WAFGetDefaultIPSet()

	if len(ipsetname) == 0 {
		return nil, errors.New("IPSet padrão não configurado")
	}

	ipset, err := WAFGetIPSetByName(wafregional, ipsetname)

	if err != nil {
		return nil, err
	}

	ipsetres, err := WAFGetIPSet(wafregional, *ipset.IPSet.IPSetId)

	if err != nil {
		return nil, err
	}

	ips := WAFListIPSetIPs(ipsetres)

	return ips, nil
}

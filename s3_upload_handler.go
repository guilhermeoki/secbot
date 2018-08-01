package secbot

import (
	"bytes"
	"fmt"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/levigross/grequests"
	"github.com/nlopes/slack"
	//"golang.org/x/text/transform"
	//"golang.org/x/text/unicode/norm"
	"math/rand"
	"regexp"
	"strings"
)

func S3UploadHandlerStart() {

	RegisterHandler("s3")

	AddCommand(Command{
		Regex:              regexp.MustCompile("s3 (?P<command>set account) (?P<account>\\S+) (?P<region>\\S+) (?P<bucket>\\S+)"),
		Help:               "Define a conta e o bucket do S3",
		Usage:              "s3 set account <account> <region> <bucket>",
		Handler:            S3SetDefaultAccountCommand,
		HandlerName:        "s3",
		RequiredPermission: "s3",
		Parameters: map[string]string{
			"account": "\\S+",
			"region":  "\\S+",
			"bucket":  "\\S+",
		}})
}

/*
Uploads a Slack shared file to S3 and returns the link
*/
func S3Upload(ev *slack.MessageEvent) {
	account, _ := GetHandlerConfig("s3", "default_account")
	region, _ := GetHandlerConfig("s3", "default_region")
	bucket, _ := GetHandlerConfig("s3", "default_bucket")

	for _, files := range ev.Files {
		fmt.Println(files.Name)

		if len(account) == 0 || len(region) == 0 || len(bucket) == 0 {
			PostMessage(ev.Channel, fmt.Sprintf("@%s Conta não configurada\n"+
				"Utilize `s3 set account <account> <region> <bucket>` para setar a conta", files.User))
			return
		}

		sess, _ := AWSGetSession(account, region)

		s3svc := s3.New(sess)

		/*

			file_name := make([]byte, len(files.Name))

			t := transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)
			_, _, err := t.Transform(file_name, []byte(files.Name), true)

		*/

		var headers = make(map[string]string)

		headers["Authorization"] = fmt.Sprintf("Bearer %s", slack_token.Buffer())

		println(headers["Authorization"])

		opts := grequests.RequestOptions{Headers: headers}

		resp, _ := grequests.Get(files.URLPrivateDownload, &opts)

		body := bytes.NewReader(resp.Bytes())

		var fname = fmt.Sprintf("%d_%s", rand.Intn(100000), files.Name)

		objinput := s3.PutObjectInput{
			Body:   body,
			Bucket: &bucket,
			Key:    &fname,
		}

		_, err := s3svc.PutObject(&objinput)

		if err != nil {
			PostMessage(ev.Channel, fmt.Sprintf("Erro efetuando upload: %s", err.Error()))
		} else {
			url := fmt.Sprintf("https://s3.amazonaws.com/%s/%s", bucket, fname)
			PostMessage(ev.Channel, url)
		}
	}
}

/*
Sets S3 default account and bucket for upload.

HandlerName

 s3

RequiredPermision

 s3

Regex

 s3 (?P<command>set account) (?P<account>\\S+) (?P<region>\\S+) (?P<bucket>\\S+)

Usage

 s3 set account <account> <region> <bucket>
*/
func S3SetDefaultAccountCommand(md map[string]string, ev *slack.MessageEvent) {
	if !AWSHasProfile(md["account"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Conta `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["account"], strings.Join(WAFGetProfilesWithDefault(), "\n")))
		return
	}

	if !AWSHasRegion(md["region"]) {
		PostMessage(ev.Channel, fmt.Sprintf("@%s Região `%s` inválida, os valores possíveis são:\n%s",
			ev.Username, md["region"], strings.Join(AWSListRegions(), "\n")))
		return
	}

	SetHandlerConfig("s3", "default_account", md["account"])
	SetHandlerConfig("s3", "default_region", md["region"])
	SetHandlerConfig("s3", "default_bucket", md["bucket"])
	PostMessage(ev.Channel, fmt.Sprintf("@%s Conta padrão setada para `%s`, região `%s`, bucket `%s`",
		ev.Username, md["account"], md["region"], md["bucket"]))

}

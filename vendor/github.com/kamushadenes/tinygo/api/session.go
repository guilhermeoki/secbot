package api

import (
	"fmt"
	"encoding/json"
	"github.com/levigross/grequests"
	"regexp"
	"strings"
	"github.com/pkg/errors"
)

var url = "https://app.tinyletter.com/__svcbus__/"

type Session struct {
	Session  *grequests.Session
	Username *string
	Password *string
	Token    *string
}

type Payload struct {
	Service *string
	Data    *string
	Token   *string
}

var DEFAULT_MESSAGE_STATUSES []string

var token string

func init() {
	DEFAULT_MESSAGE_STATUSES = append(DEFAULT_MESSAGE_STATUSES, "sent")
	DEFAULT_MESSAGE_STATUSES = append(DEFAULT_MESSAGE_STATUSES, "sending")
}

type Statuses struct {
	Status []string `json:"status"`
}

func (s Session) getCookiesAndToken() *string {
	resp, _ := s.Session.Get("https://app.tinyletter.com", nil)

	token_pattern := regexp.MustCompile("csrf_token=\"([^\"]+)\"")

	token = strings.Split(string(token_pattern.Find(resp.Bytes())), "\"")[1]

	s.Token = &token

	return &token

}

func (s Session) GetRequestOptions() *grequests.RequestOptions {
	var headers = make(map[string]string)
	headers["Accept"] = "application/json, text/javascript, */*; q=0.01"

	var opts = grequests.RequestOptions{
		Headers: headers,
	}

	return &opts
}

func (s Session) CreatePayload(service string, data interface{}, token string) interface{} {
	var payload []interface{}
	var payload1 []interface{}
	var payload2 []interface{}

	payload2 = append(payload2, service)
	payload2 = append(payload2, data)
	payload1 = append(payload1, payload2)
	payload = append(payload, payload1)
	payload = append(payload, make([]string, 0))
	payload = append(payload, token)

	return payload

}

func (s Session) Login() {
	s.getCookiesAndToken()
	var reqdata []interface{}

	reqdata = append(reqdata, s.Username)
	reqdata = append(reqdata, s.Password)
	reqdata = append(reqdata, nil)
	reqdata = append(reqdata, nil)
	reqdata = append(reqdata, nil)
	reqdata = append(reqdata, nil)

	s.Request("service:User.loginService", reqdata)
	//s.Request()
}

func (s Session) Request(service string, data interface{}) (map[string]interface{}, error) {
	payload := s.CreatePayload(service, data, token)

	//_, _ := json.Marshal(payload)

	var headers = make(map[string]string)
	headers["Content-Type"] = "application/json"

	opts := grequests.RequestOptions{
		JSON:    payload,
		Headers: headers,
	}

	resp, err := s.Session.Post(url, &opts)

	var res interface{}
	var nres map[string]interface{}

	json.Unmarshal(resp.Bytes(), &res)

	switch x := res.(type) {
	case map[string]interface{}:
		fmt.Println(x)
		return nil, errors.New("Login Failed")
	}

	x := res.([]interface{})[0]
	x2 := x.([]interface{})[0]

	nres = x2.(map[string]interface{})

	return nres, err
}

func (s Session) GetProfile() (map[string]interface{}, error) {
	return s.Request("service:User.currentUser", nil)
}

func (s Session) CountMessage() (map[string]interface{}, error) {
	return s.Request("count:Message", DEFAULT_MESSAGE_STATUSES)
}

func fmtPaging(offset int, count int) string {
	if offset == 0 && count == 0 {
		return ""
	} else {
		return fmt.Sprintf("%s, %s", offset, count)
	}
}

func (s Session) GetMessages(order string, offset int, count int, content bool) (map[string]interface{}, error) {
	var reqdata []interface{}

	var status Statuses

	status.Status = DEFAULT_MESSAGE_STATUSES

	reqdata = append(reqdata, &status)
	reqdata = append(reqdata, order)
	reqdata = append(reqdata, fmtPaging(offset, count))

	var service = "query:Message.stats"

	if content {
		service += ", Message.content"
	}

	return s.Request(service, reqdata)

}

func (s Session) GetDrafts(order string, offset int, count int, content bool) (map[string]interface{}, error) {
	var reqdata []interface{}

	var status Statuses

	var statuses []string

	statuses = append(statuses, "draft")

	status.Status = statuses

	reqdata = append(reqdata, &status)
	reqdata = append(reqdata, order)
	reqdata = append(reqdata, fmtPaging(offset, count))

	var service = "query:Message.stats"

	if content {
		service += ", Message.content"
	}

	return s.Request(service, reqdata)
}

func (s Session) GetMessage(messageId string) (map[string]interface{}, error) {
	var reqdata []string
	reqdata = append(reqdata, messageId)
	return s.Request("find:Message.stats, Message.content", reqdata)
}

func (s Session) CountURLs() (map[string]interface{}, error) {
	return s.Request("count:Message_Url", nil)
}

func (s Session) GetURLs(order string, offset int, count int) (map[string]interface{}, error) {
	var reqdata []string
	reqdata = append(reqdata, "")
	reqdata = append(reqdata, order)
	reqdata = append(reqdata, fmtPaging(offset, count))
	return s.Request("query:Message_Url", reqdata)
}

func (s Session) GetMessageURLs(messageId string, order string) (map[string]interface{}, error) {
	var reqdata []interface{}

	var msg_id = make(map[string]string)

	msg_id["message_id"] = messageId

	reqdata = append(reqdata, msg_id)
	reqdata = append(reqdata, order)
	reqdata = append(reqdata, "")
	return s.Request("query:Message_Url", reqdata)
}

func (s Session) CountSubscribers() (map[string]interface{}, error) {
	return s.Request("count:Contact", nil)
}

func (s Session) GetSubscribers(order string, offset int, count int) (map[string]interface{}, error) {
	var reqdata []string
	reqdata = append(reqdata, "")
	reqdata = append(reqdata, order)
	reqdata = append(reqdata, fmtPaging(offset, count))
	return s.Request("query:Contact.stats", reqdata)
}

func (s Session) DeleteSubscribers(subscribers []float64) (map[string]interface{}, error) {
	return s.Request("delete:Contact", subscribers)
}

func (s Session) GetSubscriber(subscriberId string) (map[string]interface{}, error) {
	var reqdata []string
	reqdata = append(reqdata, subscriberId)
	return s.Request("find:Contact.stats", reqdata)
}

func (s Session) CreateDraft() *Draft {
	var d Draft

	d.Session = s

	return &d
}

func (s Session) EditDraft(messageId string) *Draft {
	var d Draft
	d.MessageID = messageId
	d.Session = s

	return d.Fetch()
}

/*

token_pat = re.compile(r'csrf_token = "([^"]+)"')

*/

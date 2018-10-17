package api

type Draft struct {
	Session   Session
	MessageID string
	Data      map[string]interface{}
}

func (d Draft) Fetch() *Draft {
	var reqdata []string
	reqdata = append(reqdata, d.MessageID)
	resp, _ := d.Session.Request("find:Message.content", reqdata)

	d.Data = resp

	return &d
}

func (d Draft) GetSubject() string {
	return d.Data["subject"].(string)
}

func (d Draft) SetSubject(subject string) {
	d.Data["subject"] = subject
}

func (d Draft) Save() *Draft {
	var reqdata []interface{}
	reqdata = append(reqdata, d.Data)
	resp, _ := d.Session.Request("save:Message", reqdata)

	d.Data = resp
	d.MessageID = d.Data["id"].(string)

	return &d
}

func (d Draft) GetBody() string {
	return d.Data["content"].(map[string]interface{})["html"].(string)
}

func (d Draft) SetBody(value string) {
	d.Data["subject"].(map[string]string)["html"] = value
}

func (d Draft) GetPublicMessage() bool {
	return d.Data["public_message"].(bool)
}

func (d Draft) SetPublicMessage(value bool) {
	d.Data["public_message"] = value
}

func (d Draft) SendPreview() *Draft {
	var reqdata []interface{}
	reqdata = append(reqdata, d.Data)
	resp, _ := d.Session.Request("method:queuePreview", reqdata)

	d.Data = resp

	return &d
}

func (d Draft) Send() *Draft {
	var reqdata []interface{}
	reqdata = append(reqdata, d.Data)
	resp, _ := d.Session.Request("method:queue", reqdata)

	d.Data = resp

	return &d
}

func (d Draft) Delete() *Draft {
	var reqdata []interface{}
	reqdata = append(reqdata, d.MessageID)
	resp, _ := d.Session.Request("delete:Message", reqdata)

	d.Data = resp

	return &d
}

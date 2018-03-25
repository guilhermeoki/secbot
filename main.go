package main

import (
	"database/sql"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

var logger = logrus.New()

var api = GetAPI()

var name = "secbot"

var botid, _ = GetID()

var logs_channel = "bottest"

var db *sql.DB

var latency time.Duration

var starttime = time.Now()

var masteruser = "kamushadenes"

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

var slack_token, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("SLACK_TOKEN")))

func GetAPI() *slack.Client {
	api := slack.New(string(slack_token.Buffer()))

	slack_token.Destroy()

	return api
}

func StartHandlers() {
	TheEndHandlerStart()
	SlackHandlerStart()
	AuthHandlerStart()
	CreditCardHandlerStart()
	AWSHandlerStart()
	WAFHandlerStart()
	StoneGIMHandlerStart()
	GitHubHandlerStart()
	ReadmeIOHandlerStart()
	TinyLetterHandlerStart()
	S3UploadHandlerStart()
}

func init() {
	formatter := new(prefixed.TextFormatter)
	formatter.FullTimestamp = true
	logger.Formatter = formatter
	logger.Level = logrus.InfoLevel

	formatter.SetColorScheme(&prefixed.ColorScheme{
		PrefixStyle:    "blue+b",
		TimestampStyle: "white+h",
	})

}

func GetCaller() (string, string) {

	// we get the callers as uintptrs - but we just need 1
	fpcs := make([]uintptr, 1)

	// skip 3 levels to get to the caller of whoever called Caller()
	n := runtime.Callers(3, fpcs)
	if n == 0 {
		return "n/a", "" // proper error her would be better
	}

	// get the info of the actual function that's in the pointer
	fun := runtime.FuncForPC(fpcs[0] - 1)
	if fun == nil {
		return "n/a", ""
	}

	fl, _ := fun.FileLine(fun.Entry())

	return fun.Name(), fl
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

func main() {
	logger.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("SecBot is starting ...")

	logger.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Performing mlock() ...")

	// Mlockall prevents all current and future pages from being swapped out.
	unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)

	logger.WithFields(logrus.Fields{
		"prefix": "main",
	}).Info("Activating MemGuard ...")

	memguard.CatchInterrupt(func() {
		logger.WithFields(logrus.Fields{
			"prefix": "main",
		}).Warn("Interrupt signal received. Exiting ...")
	})

	// Make sure to destroy all LockedBuffers when returning.
	defer memguard.DestroyAll()

	Bootstrap()

	db, _ = GetDB()

	defer db.Close()

	StartHandlers()

	//logger := log.New(os.Stdout, "slack-bot: ", log.Lshortfile|log.LstdFlags)
	//slack.SetLogger(logger)
	//api.SetDebug(true)

	rtm := api.NewRTM()
	go rtm.ManageConnection()

	for msg := range rtm.IncomingEvents {
		switch ev := msg.Data.(type) {
		case *slack.HelloEvent:
			// Ignore hello

		case *slack.ConnectedEvent:
			logger.WithFields(logrus.Fields{
				"prefix":            "rtm.IncomingEvents",
				"infos":             ev.Info,
				"connectionCounter": ev.ConnectionCount,
			}).Info("Connected Successfully")

			go JoinChannels()

		case *slack.FileSharedEvent:
			logger.WithFields(logrus.Fields{
				"prefix": "rtm.IncomingEvents",
				"id":     ev.FileID,
				"type":   ev.Type,
				"name":   ev.File.Name,
				"user":   ev.File.User,
			}).Info("File Shared")

		case *slack.MessageEvent:
			if ev.User != botid {

				if ev.File != nil && strings.HasPrefix(ev.Channel, "D") {
					go S3Upload(ev)
					continue
				}

				logger.WithFields(logrus.Fields{
					"prefix":  "rtm.IncomingEvents",
					"message": ev,
				}).Debug("New Message")

				if AtBot(ev.Text) {
					l := strings.Split(ev.Text, " ")
					if len(l) >= 2 {
						if strings.ToUpper(l[1]) == "PING" {

							user, _ := GetUser(ev.User)

							ev.Username = user.Name

							PostMessage(ev.Channel, fmt.Sprintf("@%s PONG", ev.Username))
							continue
						} else if strings.ToUpper(l[1]) == "STATUS" {
							user, _ := GetUser(ev.User)

							ev.Username = user.Name

							msg := fmt.Sprintf("@%s\n*### Status Report ###*\n", ev.Username)
							msg += fmt.Sprintf("\n*Start Time:* %s", starttime.String())
							msg += fmt.Sprintf("\n*Uptime:* %s", time.Now().Sub(starttime))
							msg += fmt.Sprintf("\n*Latency:* %s", latency)

							PostMessage(ev.Channel, msg)

						}
					}
				}

				for _, c := range interceptors {
					n1 := c.Regex.SubexpNames()
					ntext := strings.Join(strings.Split(ev.Text, " "), "")
					r1 := c.Regex.FindAllStringSubmatch(ntext, -1)

					if len(r1) > 0 {
						r2 := r1[0]

						md := map[string]string{}
						for i, n := range r2 {
							md[n1[i]] = n
						}

						if len(r2) > 0 {

							user, _ := GetUser(ev.User)

							ev.Username = user.Name

							logger.WithFields(logrus.Fields{
								"prefix":   "main",
								"channel":  ev.Channel,
								"user":     ev.User,
								"username": ev.Username,
							}).Info("Card Detected")

							go c.Handler(md, ev)
						}
					}
				}

				for _, c := range commands {
					n1 := c.Regex.SubexpNames()
					r1 := c.Regex.FindAllStringSubmatch(ev.Text, -1)

					if len(r1) > 0 {
						r2 := r1[0]

						md := map[string]string{}
						for i, n := range r2 {
							md[n1[i]] = n
						}

						if len(r2) > 0 {

							user, _ := GetUser(ev.User)

							ev.Username = user.Name

							logger.WithFields(logrus.Fields{
								"prefix":   "main",
								"channel":  ev.Channel,
								"user":     ev.User,
								"username": ev.Username,
								"command":  md["command"],
								"text":     ev.Text,
							}).Info("Command Received")

							go c.Handler(md, ev)
						}
					}
				}
			}

		case *slack.PresenceChangeEvent:
			logger.WithFields(logrus.Fields{
				"prefix":   "rtm.IncomingEvents",
				"presence": ev,
			}).Debug("Presence Change")

		case *slack.LatencyReport:
			logger.WithFields(logrus.Fields{
				"prefix":  "rtm.IncomingEvents",
				"latency": ev.Value,
			}).Info("Latency Status")

			latency = ev.Value

		case *slack.RTMError:
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "rtm.IncomingEvents",
				"caller": caller,
				"file":   file,
				"error":  ev.Error(),
			}).Error("An Error Occurred")

		case *slack.InvalidAuthEvent:
			caller, file := GetCaller()
			logger.WithFields(logrus.Fields{
				"prefix": "rtm.IncomingEvents",
				"caller": caller,
				"file":   file,
			}).Error("Invalid Credentials")
			return

		default:

			// Ignore other events..
			// fmt.Printf("Unexpected: %v\n", msg.Data)
		}
	}
}

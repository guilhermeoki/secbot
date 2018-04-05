/*
This bot aims to provide chat ops and security-related features.
*/
package secbot

import (
	"database/sql"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"golang.org/x/sys/unix"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var logger = logrus.New()

var api = GetAPI()

var botname = "secbot"

var botid, _ = GetID()

var logs_channel = "security_logs"

var db *sql.DB

var latency time.Duration

var starttime = time.Now()

var masteruser = "kamushadenes"

var slack_token, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("SLACK_TOKEN")))

// Reads the <slack_token> variable and creates a new Slack client, destroying the token afterwards.
func GetAPI() *slack.Client {
	api := slack.New(string(slack_token.Buffer()))

	//slack_token.Destroy()

	return api
}

/*
Calls InterceptorInterceptorStart(), registering and logging the interceptor and its handlers.
*/
func StartInterceptors() {
	// Ensure CreditCardInterceptor is listed first to prevent credit card logging.
	CreditCardInterceptorStart()
	LoggingInterceptorStart()
}

/*
Calls HandlerHandlerStart(), registering and logging the handler and its commands.
*/
func StartHandlers() {
	TheEndHandlerStart()
	SlackHandlerStart()
	AuthHandlerStart()
	AWSHandlerStart()
	WAFHandlerStart()
	StoneGIMHandlerStart()
	GitHubHandlerStart()
	ReadmeIOHandlerStart()
	TinyLetterHandlerStart()
	S3UploadHandlerStart()
}

// Initializes the logger and sets logrus colors.
func init() {
	formatter := new(prefixed.TextFormatter)
	formatter.FullTimestamp = true
	logger.Formatter = formatter
	logger.Level = logrus.InfoLevel

	formatter.SetColorScheme(&prefixed.ColorScheme{
		PrefixStyle:    "blue+b",
		TimestampStyle: "white+h",
	})

	unknown_command_phrases = append(unknown_command_phrases, "¿QUE?")
	unknown_command_phrases = append(unknown_command_phrases, "Err... oi??")
	unknown_command_phrases = append(unknown_command_phrases, "Num intendi u qui ele falô")
	unknown_command_phrases = append(unknown_command_phrases, "Abre a boca pra falar!")

}

// Gets the caller of a function, useful when printing out errors.
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

func Run() {
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

	StartInterceptors()
	StartHandlers()

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

			go JoinChannels(true)

		case *slack.FileSharedEvent:
			logger.WithFields(logrus.Fields{
				"prefix": "rtm.IncomingEvents",
				"id":     ev.FileID,
				"type":   ev.Type,
				"name":   ev.File.Name,
				"user":   ev.File.User,
			}).Info("File Shared")

		case *slack.MessageEvent:
			var proceedInterceptor = true

			for _, c := range interceptors {
				if proceedInterceptor {
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

							if len(ev.User) > 0 {
								user, _ := GetUser(ev.User)

								if user != nil {
									ev.Username = user.Name
								}

								go c.Handler(md, ev)

								proceedInterceptor = c.Continue
							}

						}
					}
				}

			}

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
							msg += fmt.Sprintf("\n*Start Time:* %s", starttime.Format("2006-01-02T15:04:05"))
							msg += fmt.Sprintf("\n*Uptime:* %s", time.Now().Sub(starttime))
							msg += fmt.Sprintf("\n*Latency:* %s", latency)
							msg += fmt.Sprintf("\n*Handlers:* %d", len(handlers))
							msg += fmt.Sprintf("\n*Commands:* %d", len(commands))
							msg += fmt.Sprintf("\n*Interceptors:* %d", len(interceptors))

							PostMessage(ev.Channel, msg)

							continue

						} else if strings.ToUpper(l[1]) == "HELP" {

							msg := fmt.Sprintf("@%s\n*### Módulos Disponíveis ###*\n", ev.Username)

							for _, v := range handlers {
								msg += fmt.Sprintf("\n%s - `%s help`", v, v)
							}

							PostMessage(ev.Channel, msg)

							continue

						}
					}
				}

				if AtBot(ev.Text) {
					var matched = false
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

								matched = true

								user, _ := GetUser(ev.User)

								if user != nil {

									ev.Username = user.Name
								}

								logger.WithFields(logrus.Fields{
									"prefix":   "main",
									"channel":  ev.Channel,
									"user":     ev.User,
									"username": ev.Username,
									"command":  md["command"],
									"text":     ev.Text,
								}).Info("Command Received")

								if &c.RequiredPermission != nil && len(c.RequiredPermission) > 0 {
									if !IsAuthorized(c.RequiredPermission, ev.Username) {
										Unauthorized(md, ev)
										break
									}
								}

								go c.Handler(md, ev)

								break
							}
						}
					}

					if !matched {
						rand.Seed(time.Now().Unix())

						n := rand.Int() % len(unknown_command_phrases)

						PostMessage(ev.Channel, fmt.Sprintf("@%s %s", ev.Username, unknown_command_phrases[n]))
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

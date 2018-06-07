/*
This bot aims to provide chat ops and security-related features.
*/
package secbot

import (
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"github.com/nlopes/slack"
	"github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"golang.org/x/sys/unix"
)

var logger = logrus.New()

var api = GetAPI()

var botname = os.Getenv("BOT_NAME")

var botid, _ = GetID()

var logs_channel = os.Getenv("CHANNEL_NAME")

var db *sql.DB

var latency time.Duration

var starttime = time.Now()

var masteruser = os.Getenv("MASTER_USER")

var slack_token, _ = memguard.NewImmutableFromBytes([]byte(os.Getenv("SLACK_TOKEN")))

var First_Time = false

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
	UpdateHandlerStart()
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
			var text_veri = ""
			var user_ver = ""
			err := ev.SubMessage
			if err == nil {
				text_veri = ev.Text
				user_ver = ev.User
			} else {
				text_veri = ev.SubMessage.Text
				user_ver = ev.SubMessage.User
			}

			for _, c := range interceptors {
				if proceedInterceptor {
					n1 := c.Regex.SubexpNames()
					ntext := strings.Join(strings.Split(text_veri, " "), "")
					r1 := c.Regex.FindAllStringSubmatch(ntext, -1)

					if len(r1) > 0 {
						r2 := r1[0]

						md := map[string]string{}
						for i, n := range r2 {
							md[n1[i]] = n
						}

						if len(r2) > 0 {

							if len(user_ver) > 0 {
								user, _ := GetUser(user_ver)

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

			if !First_Time {
				First_Time = true
				msg := fmt.Sprintf("\n*### Update Report ###*\n")
				msg += fmt.Sprintf("\n*Start Time:* %s", starttime.Format("2006-01-02T15:04:05"))
				msg += fmt.Sprintf("\n*Handlers:* %d", len(handlers))
				msg += fmt.Sprintf("\n*Commands:* %d", len(commands))
				msg += fmt.Sprintf("\n*Interceptors:* %d", len(interceptors))

				PostMessage(logs_channel, msg)
				continue
			}

			if user_ver != botid {

				if ev.File != nil && strings.HasPrefix(ev.Channel, "D") {
					go S3Upload(ev)
					continue
				}

				logger.WithFields(logrus.Fields{
					"prefix":  "rtm.IncomingEvents",
					"message": ev,
				}).Debug("New Message")

				if AtBot(text_veri) {
					l := strings.Split(text_veri, " ")
					if len(l) >= 2 {
						if strings.ToUpper(l[1]) == "PING" {

							user, _ := GetUser(user_ver)

							ev.Username = user.Name

							PostMessage(ev.Channel, fmt.Sprintf("@%s PONG", ev.Username))
							continue
						} else if strings.ToUpper(l[1]) == "STATUS" {
							user, _ := GetUser(user_ver)

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

				if AtBot(text_veri) {
					var matched = false
					for _, c := range commands {
						n1 := c.Regex.SubexpNames()
						r1 := c.Regex.FindAllStringSubmatch(text_veri, -1)

						if len(r1) > 0 {
							r2 := r1[0]

							md := map[string]string{}
							for i, n := range r2 {
								md[n1[i]] = n
							}

							if len(r2) > 0 {

								matched = true

								user, _ := GetUser(user_ver)

								if user != nil {

									ev.Username = user.Name
								}

								logger.WithFields(logrus.Fields{
									"prefix":   "main",
									"channel":  ev.Channel,
									"user":     user_ver,
									"username": ev.Username,
									"command":  md["command"],
									"text":     text_veri,
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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/urfave/cli/v2"
)

type LOG_LEVEL struct{}
type CLIENT_ID struct{}
type CLIENT_SECRET struct{}

func main() {
	var l log.Logger
	var llvl string
	ctx := context.Background()

	app := &cli.App{
		Name:  "AuditLab",
		Usage: "tool for auditing",
		Before: func(cCtx *cli.Context) error {
			// add logger and log level to context
			ctx = contextWithLogger(ctx, newLogger(llvl))
			ctx = context.WithValue(ctx, LOG_LEVEL{},  llvl)
			// add github creds to context
			ctx = context.WithValue(ctx, CLIENT_ID{},  os.Getenv("GITHUB_CLIENT_ID"))
			ctx = context.WithValue(ctx, CLIENT_SECRET{},  os.Getenv("GITHUB_CLIENT_SECRET"))

			l = loggerFromContext(ctx)
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "logLevel",
				Aliases:     []string{"log"},
				Usage:       "debug, info, warn, error",
				Value:       "warn",
				Destination: &llvl,
				EnvVars:     []string{"LOG_LEVEL"},
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "whoami",
				Usage: "github user identification",
				Action: func(cCtx *cli.Context) error {

					level.Info(l).Log("msg", "whoami")
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "github login",
				Action: func(cCtx *cli.Context) error {
					level.Info(l).Log("msg", "login", "client id", ctx.Value("client_id"))
					login(ctx)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		level.Error(l).Log("msg", "fatal", "error", err)
	}
}

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type RequestTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"tokenType"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
	Interval         int    `json:"interval"`
}

// postForm function is a generic allowing posting of form data to a given URI and returning
// the correct response
func postForm[V DeviceCodeResponse | RequestTokenResponse](ctx context.Context, uri string, form url.Values) (V, error) {
	var r V
	l := loggerFromContext(ctx)

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		return r, err
	}

	// Add the explicit headers to the request.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// toggle debugging
	var client http.Client
	if ctx.Value(LOG_LEVEL{}) == "debug" {
		client = http.Client{
			Transport: &loggingTransport{},
		}
	} else {
		client = http.Client{}
	}

	// Send the request.
	resp, err := client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	level.Info(l).Log("msg", "request Device Code", "status_code", resp.StatusCode)

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("failed to get device code. status_code: %d", resp.StatusCode)
	}

	// Get the response body as a JSON object.
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return r, err
	}

	// Close the response body.
	resp.Body.Close()
	return r, nil
}

// requestDeviceCode function performs a POST request to https://github.com/login/device/code
func requestDeviceCode(ctx context.Context, clientID, secretID string) (DeviceCodeResponse, error) {
	var r DeviceCodeResponse
	uri := "https://github.com/login/device/code"

	// Add the client ID to the request.
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("secret_id", secretID)

	r, err := postForm[DeviceCodeResponse](ctx, uri, form)
	if err != nil {
		return r, err
	}

	return r, nil
}

// requestToken function performs a POST request to https://github.com/login/oauth/access_token
func requestToken(ctx context.Context, clientID, deviceCode string) (RequestTokenResponse, error) {
	var r RequestTokenResponse
	uri := "https://github.com/login/oauth/access_token"

	// Add the client ID to the request.
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("device_code", deviceCode)
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	r, err := postForm[RequestTokenResponse](ctx, uri, form)
	if err != nil {
		return r, err
	}

	return r, nil
}

// wait function sleep for specified interval
func wait(l log.Logger, interval int) {
	level.Info(l).Log("msg", "sleep", "interval", interval, "unit", "seconds")
	time.Sleep(time.Duration(interval) * time.Second)
}

// pollForToken function polls https://github.com/login/oauth/access_token at the specified interval
// until GitHub responds with an access_token parameter instead of an error parameter.
// Then, it writes the user access token to a file and restricts the permissions on the file.
func pollForToken(ctx context.Context, clientID, deviceCode string, interval int) error {
	l := loggerFromContext(ctx)
	i := interval
	var t RequestTokenResponse

	Loop:
	for {
		t, err := requestToken(ctx, clientID, deviceCode)
		if err != nil {
			return err
		}

		if t.Error != "" {
			level.Info(l).Log("msg", "poll", "status", "error", "error", t.Error, "error_description", t.ErrorDescription, "interval", t.Interval)
		} else {
			level.Info(l).Log("msg", "poll", "status", "success", "access_token", t.AccessToken)
		}

		// update interval if available in response
		value := reflect.ValueOf(t)
		field := value.FieldByName("Interval")
		if field.IsValid() && !field.IsZero() {
			i = t.Interval
		}

		switch t.Error {
		case "authorization_pending":
			// The user has not yet entered the code.
			wait(l, i)
		case "slow_down":
			// The app polled too fast.
			// Wait for the interval plus 5 seconds, then poll again.
			wait(l, i+5)
		case "expired_token":
			// The `device_code` expired, and the process needs to restart.
			return fmt.Errorf(t.Error)
		case "access_denied":
			// The user cancelled the process. Stop polling.
			return fmt.Errorf(t.Error)
		default:
			break Loop
		}
	}

	// get home dir
	home, err := os.UserHomeDir()
	if err != nil {
		level.Error(l).Log("msg", "failed to get home directory", "error", err)
		panic(err)
	}

	// create out dir
	d := home + "/.github"
	err = os.MkdirAll(d, 0744)
	if err !=	nil {
		level.Error(l).Log("msg", "failed to write access_token to file", "directory", d, "error", err)
		panic(err)
	}

	// write access token
	filename := d + "/credentials"
	err = os.WriteFile(filename, []byte(t.AccessToken), 0644)
	if err !=	nil {
		level.Error(l).Log("msg", "failed to write access token to file", "filename", filename, "error", err)
		panic(err)
	}

	fmt.Printf("Successfully authenticated!")
	return nil
}

// login functionc alls the request_device_code function and gets the verification_uri, user_code, device_code,
// and interval parameters from the response.
// It prompts users to enter the user_code from the previous step.
// It calls the poll_for_token to poll GitHub for an access token.
// It lets the user know that authentication was successful.
func login(ctx context.Context) {
	l := loggerFromContext(ctx)
	c := ctx.Value(CLIENT_ID{}).(string)
	s := ctx.Value(CLIENT_SECRET{}).(string)

	// get device code
	r, err := requestDeviceCode(ctx, c, s)
	if err != nil {
		panic(err)
	}

	level.Info(l).Log("msg", "response", "device_code", r.DeviceCode, "user_code", r.UserCode, "verification_uri", r.VerificationURI)

	// provide user instructions
	fmt.Printf("Visit: %s\n", r.VerificationURI)
	fmt.Printf("Provide code: %s\n", r.UserCode)

	// prompt user to continue
	var userConfirm string
	fmt.Scanf("%s", &userConfirm)

	// poll for access token
	if err = pollForToken(ctx, c, r.DeviceCode, r.Interval); err != nil {
		level.Error(l).Log("msg", "failed to retrieve access token", "error", err)
	}

}

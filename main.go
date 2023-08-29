package main

import (
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

func main() {
	var l *log.Logger
	var llvl string

	CLIENT_ID := os.Getenv("GITHUB_CLIENT_ID")
	SECRET_ID := os.Getenv("GITHUB_CLIENT_SECRET")

	app := &cli.App{
		Name:  "AuditLab",
		Usage: "tool for auditing",
		Before: func(cCtx *cli.Context) error {
			l = newLogger(llvl)
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "logLevel",
				Aliases:     []string{"log"},
				Usage:       "debug, info, warn, error",
				Value:       "info",
				Destination: &llvl,
				EnvVars:     []string{"LOG_LEVEL"},
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "whoami",
				Usage: "github user identification",
				Action: func(cCtx *cli.Context) error {
					level.Debug(*l).Log("msg", "whoami")
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "github login",
				Action: func(cCtx *cli.Context) error {
					level.Debug(*l).Log("msg", "login", "client id", CLIENT_ID)
					login(l, CLIENT_ID, SECRET_ID)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		level.Error(*l).Log("msg", "fatal", "error", err)
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
func postForm[V DeviceCodeResponse | RequestTokenResponse](l *log.Logger, uri string, form url.Values) (V, error) {
	var r V

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		return r, err
	}

	// Add the explicit headers to the request.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// todo: toggle debugging
	client := http.Client{
		Transport: &loggingTransport{},
	}
	// client := http.Client{}

	// Send the request.
	resp, err := client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()

	level.Debug(*l).Log("msg", "request Device Code", "status_code", resp.StatusCode)

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
func requestDeviceCode(l *log.Logger, clientID, secretID string) (DeviceCodeResponse, error) {
	var r DeviceCodeResponse
	uri := "https://github.com/login/device/code"

	// Add the client ID to the request.
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("secret_id", secretID)

	r, err := postForm[DeviceCodeResponse](l, uri, form)
	if err != nil {
		return r, err
	}

	return r, nil
}

// requestToken function performs a POST request to https://github.com/login/oauth/access_token
func requestToken(l *log.Logger, clientID, deviceCode string) (RequestTokenResponse, error) {
	var r RequestTokenResponse
	uri := "https://github.com/login/oauth/access_token"

	// Add the client ID to the request.
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("device_code", deviceCode)
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	r, err := postForm[RequestTokenResponse](l, uri, form)
	if err != nil {
		return r, err
	}

	return r, nil
}

// wait function sleep for specified interval
func wait(l *log.Logger, interval int) {
	// Wait, then poll again.
	time.Sleep(time.Duration(interval) * time.Second)
	// Printed after sleep is over
	level.Debug(*l).Log("msg", "Rest is good")
}

// pollForToken function polls https://github.com/login/oauth/access_token at the specified interval
// until GitHub responds with an access_token parameter instead of an error parameter.
// Then, it writes the user access token to a file and restricts the permissions on the file.
func pollForToken(l *log.Logger, clientID, deviceCode string, interval int) {
Loop:
	for {
		i := interval
		t, err := requestToken(l, clientID, deviceCode)

		value := reflect.ValueOf(t)
		field := value.FieldByName("Interval")
		if field.IsValid() {
			i = t.Interval
		}

		level.Debug(*l).Log("msg", "ping")
		time.Sleep(time.Duration(i) * time.Second)
		level.Debug(*l).Log("msg", "pong")

		if err == nil {
			level.Debug(*l).Log("msg", "poll for token", "access_token", t.AccessToken)
			fmt.Println("Login successful.")
			return
		}

		level.Debug(*l).Log("msg", "poll for token", "error", err)
		switch err {
		case fmt.Errorf("authorization_pending"):
			// The user has not yet entered the code.
			wait(l, i)
			break Loop
		case fmt.Errorf("slow_down"):
			// The app polled too fast.
			// Wait for the interval plus 5 seconds, then poll again.
			wait(l, i+5)
			break Loop
		case fmt.Errorf("expired_token"):
			// The `device_code` expired, and the process needs to restart.
			level.Info(*l).Log("msg", "The device code has expired. Please run `login` again.", "error", err)
			return
		case fmt.Errorf("access_denied"):
			// The user cancelled the process. Stop polling.
			level.Info(*l).Log("msg", "Login cancelled by user.", "error", err)
			return
		default:
			level.Info(*l).Log("msg", "unknown failure", "error", err)
		}
	}
}

// login functionc alls the request_device_code function and gets the verification_uri, user_code, device_code,
// and interval parameters from the response.
// It prompts users to enter the user_code from the previous step.
// It calls the poll_for_token to poll GitHub for an access token.
// It lets the user know that authentication was successful.
func login(l *log.Logger, clientID, secretID string) {
	// get device code
	r, err := requestDeviceCode(l, clientID, secretID)
	if err != nil {
		panic(err)
	}

	level.Debug(*l).Log("msg", "response", "device_code", r.DeviceCode, "user_code", r.UserCode, "verification_uri", r.VerificationURI)

	fmt.Printf("Visit: %s\n", r.VerificationURI)
	fmt.Printf("Provide code: %s\n", r.UserCode)

	var userConfirm string
	fmt.Scanf("%s", &userConfirm)
	pollForToken(l, clientID, r.DeviceCode, r.Interval)
}

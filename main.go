package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
					level.Info(*l).Log("msg", "whoami")
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "github login",
				Action: func(cCtx *cli.Context) error {
					level.Info(*l).Log("msg", "login", "client id", CLIENT_ID)
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

// parseResponse function parses a response from the GitHub REST API.
// When the response status is 200 OK or 201 Created, the function returns the parsed response body.
// Otherwise, the function prints the response and body an exits the program.
func parseResponse(l *log.Logger, resp *http.Response) (interface{}, error) {
	// // Get the response body as a string.
	// bodyBytes, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	level.Error(*l).Log("msg", "fatal", "error", err)
	// }

	// s := resp.StatusCode
	// if s != http.StatusOK || s != http.StatusCreated {
	// 	bodyString := string(bodyBytes)
	// 	level.Error(*l).Log("msg", "requestDeviceCode", "status_code", s, "error", bodyString)
	// 	return nil, errors.New("failed to post form")
	// }

	// var f map[string]interface{}
	// if err := json.Unmarshal(bodyBytes, &f); err != nil {
	// 	return nil, err
	// }

	var j interface{}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, err
	}

	return j, nil
}


type DeviceCodeResponse struct {
	DeviceCode string `json:"device_code"`
	UserCode string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn int `json:"expires_in"`
	Interval int `json:"interval"`
}

// requestDeviceCode function makes a POST request to https://github.com/login/device/code and
// returns the response.
func requestDeviceCode(l *log.Logger, clientID, secretID string) (DeviceCodeResponse, error) {
	var d DeviceCodeResponse

	uri := "https://github.com/login/device/code"

	// Add the client ID to the request.
	form := url.Values{}
	form.Add("client_id", clientID)
	form.Add("secret_id", secretID)

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, strings.NewReader(form.Encode()))
	if err != nil {
		return d, err
	}

	// Add the explicit headers to the request.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send the request.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()

	level.Debug(*l).Log("msg", "requestDeviceCode", "status_code", resp.StatusCode)

	// Check the response status code.
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("failed to get device code. status_code: %d", resp.StatusCode)
	}

	// Get the response body as a JSON object.
	err = json.NewDecoder(resp.Body).Decode(&d)
	if err != nil {
		return d, err
	}

	return d, nil
}

// requestToken function makes a POST request to https://github.com/login/oauth/access_token
// and returns the response.
func requestToken(l *log.Logger, clientID, deviceCode string) (*http.Response, error) {
	uri := "https://github.com/login/oauth/access_token"

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, nil)
	if err != nil {
		return nil, err
	}

	// Add the explicit parameters to the request.
	req.Form = url.Values{
		"client_id":   {clientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	// Add the explicit headers to the request.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Send the request.
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Close the response body.
	response.Body.Close()

	return response, nil
}

// pollForToken function polls https://github.com/login/oauth/access_token at the specified interval
// until GitHub responds with an access_token parameter instead of an error parameter.
// Then, it writes the user access token to a file and restricts the permissions on the file.
func pollForToken(l *log.Logger, clientID, deviceCode string, interval int) {

	for {
		response, err := requestToken(l, clientID, deviceCode)
		r, _ := parseResponse(l, response)

		if err != nil {
			switch err {
			case fmt.Errorf("authorization_pending"):
				// The user has not yet entered the code.
				// Wait, then poll again.
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			case fmt.Errorf("slow_down"):
				// The app polled too fast.
				// Wait for the interval plus 5 seconds, then poll again.
				time.Sleep(time.Duration(interval+5) * time.Second)
				level.Info(*l).Log("msg", "The device code has expired. Please run `login` again.", "error", err)
				continue
			case fmt.Errorf("expired_token"):
				// The `device_code` expired, and the process needs to restart.
				level.Info(*l).Log("msg", "The device code has expired. Please run `login` again.", "error", err)
				return
			case fmt.Errorf("access_denied"):
				// The user cancelled the process. Stop polling.
				level.Info(*l).Log("msg", "Login cancelled by user.", "error", err)
				return
			default:
				level.Info(*l).Log("msg", "default", "reponse", response)
				return
			}
		}

		// a := r["access_token"]
		// if err := os.WriteFile("/tmp/token", string(a, 0600); err != nil {
		// 	fmt.Print("failed to write token to file")
		// }

		fmt.Print(r)

		break
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
	fmt.Println(r)

	// // get values
	// resp, err := parseResponse(l, r)
	// if err != nil {
	// 	panic(err)
	// }
	// level.Debug(*l).Log("msg", "json", "response", resp)
	//verification_uri, user_code, device_code, interval

	// var code string
	// fmt.Println("Please visit: %s", verification_uri)
	// fmt.Println("and enter code:")
	// fmt.Scanf("%s", &code)

	// pollForToken(device_code, interval)

	// fmt.Println( "Successfully authenticated!")
}

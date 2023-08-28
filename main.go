package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	CLIENT_ID := os.Getenv("GITHUB_CLIENT_ID")
	SECRET_ID := os.Getenv("GITHUB_CLIENT_SECRET")

	app := &cli.App{
		Name:  "AuditLab",
		Usage: "tool for auditing",
		Commands: []*cli.Command{
			{
				Name:  "whoami",
				Usage: "github user identification",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("authenticated")
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "github login",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("logging in ", cCtx.Args().First())
					login(cCtx.Context, CLIENT_ID, SECRET_ID)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// parseResponse function parses a response from the GitHub REST API.
// When the response status is 200 OK or 201 Created, the function returns the parsed response body.
// Otherwise, the function prints the response and body an exits the program.
func parseResponse(response *http.Response) (map[string]interface{}, error) {

	// Get the response body as a string.
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
			log.Fatal(err)
	}

	s := response.StatusCode
	if s != http.StatusOK || s != http.StatusCreated {
		fmt.Println("Failed to post form. Status code:", s)
		bodyString := string(bodyBytes)
		fmt.Print(bodyString)
		return nil, errors.New("failed to post form")
	}

	var f map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &f); err != nil {
		return nil, err
	}

	return f, nil
}

// requestDeviceCode function makes a POST request to https://github.com/login/device/code and
// returns the response.
func requestDeviceCode(ctx context.Context, clientID, secretID string) (*http.Response, error) {
	uri := "https://github.com/login/device/code"

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, nil)
	if err != nil {
		return nil, err
	}

	// Add the explicit parameters to the request.
	req.Form = url.Values{
		"client_id": {clientID},
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

// requestToken function makes a POST request to https://github.com/login/oauth/access_token
// and returns the response.
func requestToken(clientID, deviceCode string) (*http.Response, error) {
  uri := "https://github.com/login/oauth/access_token"

	// Create a new request with the POST method.
	req, err := http.NewRequest("POST", uri, nil)
	if err != nil {
		return nil, err
	}

	// Add the explicit parameters to the request.
	req.Form = url.Values{
		"client_id": {clientID},
		"device_code": {deviceCode},
    "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
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
func pollForToken(clientID, deviceCode string, interval int) {

  for {
    response, err := requestToken(clientID, deviceCode)
		r, _ := parseResponse(response)

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
        continue
      case fmt.Errorf( "expired_token"):
        // The `device_code` expired, and the process needs to restart.
        fmt.Print( "The device code has expired. Please run `login` again.")
        return 
      case fmt.Errorf( "access_denied"):
        // The user cancelled the process. Stop polling.
        fmt.Print( "Login cancelled by user.")
        return 
			default:
				fmt.Print(response)
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
func login(ctx context.Context, clientID, secretID string) {
	// get device code
  r, err := requestDeviceCode(ctx, clientID, secretID)
	if err != nil {
		panic(err)
	}

	fmt.Print(r)
	
	// get values
	// verification_uri, user_code, device_code, interval := parseResponse(r)

	// var code string
  // fmt.Println("Please visit: %s", verification_uri)
  // fmt.Println("and enter code:")
	// fmt.Scanf("%s", &code)

  // pollForToken(device_code, interval)

  // fmt.Println( "Successfully authenticated!")
}

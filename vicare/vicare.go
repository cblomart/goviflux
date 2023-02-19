package vicare

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/billgraziano/dpapi"
	"github.com/cblomart/goviflux/config"
	"github.com/grokify/go-pkce"
)

const (
	VICARE_BASE  = "https://api.viessmann.com/iot/v1/"
	VICARE_AUTH  = "https://iam.viessmann.com/idp/v3/authorize"
	VICARE_TOKEN = "https://iam.viessmann.com/idp/v3/token"
	VICARE_SCOPE = "IoT offline_access"
)

type ViCare struct {
	UserName         string
	passWord         string
	clientId         string
	callbackUrl      string
	accesstoken      string
	refreshTokenPath string
	expires          time.Time
	refresh          time.Time
	client           *http.Client
}

type Error struct {
	Error string
}

type ViError struct {
	Message string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type Installation struct {
	Id          int
	Description string
}

type InstalationResponse struct {
	Data []Installation
}

type Gateway struct {
	Serial         string
	InstallationId int
}

type GatewayResponse struct {
	Data []Gateway
}

type Device struct {
	Id         string
	DeviceType string
}

type DeviceResponse struct {
	Data []Device
}

type FloatFeatureValue struct {
	Type  string
	Unit  string
	Value float32
}

type BoolFeatureValue struct {
	Type  string
	Value bool
}

type FeatureProperties struct {
	Active        *BoolFeatureValue  `json:",omitempty"`
	Value         *FloatFeatureValue `json:",omitempty"`
	CurrentDay    *FloatFeatureValue `json:",omitempty"`
	LastSevenDays *FloatFeatureValue `json:",omitempty"`
	CurrentMonth  *FloatFeatureValue `json:",omitempty"`
	CurrentYear   *FloatFeatureValue `json:",omitempty"`
}

type Feature struct {
	Feature    string
	Properties *FeatureProperties `json:",omitempty"`
}

type FeatureResponse struct {
	Data []Feature
}

func NewViCare(username, password, clientId, callbackUrl, refreshTokenPath string) (*ViCare, error) {
	return &ViCare{UserName: username, passWord: password, clientId: clientId, callbackUrl: callbackUrl, refreshTokenPath: refreshTokenPath, client: &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func ConfigToViCare(c *config.Config) (*ViCare, error) {
	return NewViCare(c.Username, c.Password, c.ClientId, c.CallbackUrl, c.RefreshTokenPath)
}

func (v *ViCare) GetRefreshToken() (string, error) {
	fileInfo, err := os.Stat(v.refreshTokenPath)
	if err != nil {
		return "", err
	}
	if fileInfo.Mode() != os.FileMode(int(0600)) && runtime.GOOS != "windows" {
		return "", fmt.Errorf("refresh token cache is not properly protected")
	}
	if fileInfo.ModTime().Add(180 * 25 * time.Hour).Before(time.Now()) {
		return "", nil
	}
	if fileInfo.Size() == 0 {
		return "", nil
	}
	token, err := ioutil.ReadFile(v.refreshTokenPath)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" {
		return string(token), nil
	} else {
		// use DPAPI to encrypt token
		return dpapi.Decrypt(string(token))
	}
}

func (v *ViCare) HasRefreshToken() bool {
	fileInfo, err := os.Stat(v.refreshTokenPath)
	if err != nil {
		return false
	}
	if fileInfo.Mode() != os.FileMode(int(0600)) && runtime.GOOS != "windows" {
		return false
	}
	if fileInfo.ModTime().Add(180 * 25 * time.Hour).Before(time.Now()) {
		return false
	}
	if fileInfo.Size() == 0 {
		return false
	}
	return true
}

func (v *ViCare) SaveRefreshToken(token string) error {
	if len(token) == 0 {
		return fmt.Errorf("Cannot save empty refresh token")
	}
	if runtime.GOOS != "windows" {
		err := ioutil.WriteFile(v.refreshTokenPath, []byte(token), os.FileMode(int(0600)))
		if err != nil {
			return err
		}
	}
	encToken, err := dpapi.Encrypt(token)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(v.refreshTokenPath, []byte(encToken), os.FileMode(int(0666)))
	if err != nil {
		return err
	}
	return nil
}

func (v *ViCare) AuthCheck() error {
	if len(v.accesstoken) > 0 {
		// we have an access token
		if v.refresh.After(time.Now()) {
			// access token valid
			return nil
		} else {
			// access token needs to be refreshed
			if v.HasRefreshToken() {
				// we have a refresh token
				err := v.RefreshToken()
				if err != nil && v.expires.Before(time.Now()) {
					// token expired and can't refresh
					return err
				}
				log.Println("Access token refreshed")
			} else {
				// we don't have a refresh token
				err := v.AquireToken()
				if err != nil && v.expires.Before(time.Now()) {
					// token expired and can't aquire a new one
					return err
				}
				log.Println("Access token acquired")
			}
		}
	}
	if len(v.accesstoken) == 0 {
		// we don't have an access token
		if v.HasRefreshToken() {
			// we have a refresh token
			err := v.RefreshToken()
			if err != nil {
				return err
			}
			log.Println("New access token from refresh")
		} else {
			// we don't have a refresh token
			err := v.AquireToken()
			if err != nil {
				return err
			}
			log.Println("New access token")
		}
	}
	if len(v.accesstoken) == 0 {
		return fmt.Errorf("No access token")
	}
	return nil
}

func (v *ViCare) AquireToken() error {
	// get pkce verifier
	codeVerifier := pkce.NewCodeVerifier()
	codeChallenge := pkce.CodeChallengeS256(codeVerifier)
	// set parameters for authorization request
	params := url.Values{}
	params.Set("client_id", v.clientId)
	params.Set("redirect_uri", v.callbackUrl)
	params.Set("scope", VICARE_SCOPE)
	params.Set("response_type", "code")
	params.Set("code_challenge_method", "S256")
	params.Set("code_challenge", codeChallenge)
	// prepare the request to authorize
	authrequest, err := http.NewRequest("GET", fmt.Sprintf("%s?%s", VICARE_AUTH, params.Encode()), nil)
	if err != nil {
		return err
	}
	authrequest.SetBasicAuth("cblomart@gmail.com", "1Luv@ur3")
	// execute the query to authorize
	authresponse, err := v.client.Do(authrequest)
	if err != nil {
		return err
	}
	// check for error
	if authresponse.StatusCode/100 >= 4 {
		vicareerror := &Error{}
		json.NewDecoder(authresponse.Body).Decode(vicareerror)
		return fmt.Errorf(vicareerror.Error)
	}
	// get redirect
	redirect := authresponse.Header.Get("Location")
	if len(redirect) == 0 {
		return fmt.Errorf("Auhorization code request didn't redirect")
	}
	redirectUrl, err := url.Parse(redirect)
	if err != nil {
		return err
	}
	// get code
	code := redirectUrl.Query().Get("code")
	if len(code) == 0 {
		return fmt.Errorf("Auhorization code request didn't provide a code")
	}
	// set parameters for token request
	params = url.Values{}
	params.Set("client_id", v.clientId)
	params.Set("grant_type", "authorization_code")
	params.Set("redirect_uri", v.callbackUrl)
	params.Set("code_verifier", codeVerifier)
	params.Set("code", code)
	// prepare the request to token
	tokenrequest, err := http.NewRequest("POST", VICARE_TOKEN, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	tokenrequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// execute the query to token
	tokenresponse, err := v.client.Do(tokenrequest)
	if err != nil {
		return err
	}
	// check for error
	if tokenresponse.StatusCode/100 >= 4 {
		vicareerror := &Error{}
		json.NewDecoder(tokenresponse.Body).Decode(vicareerror)
		return fmt.Errorf(vicareerror.Error)
	}
	// read token response
	tokens := &TokenResponse{}
	json.NewDecoder(tokenresponse.Body).Decode(tokens)
	// set the expiry time
	err = v.SaveRefreshToken(tokens.RefreshToken)
	if err != nil {
		return fmt.Errorf("Could not save refresh token")
	}
	v.expires = time.Now().Add(time.Second * time.Duration(tokens.ExpiresIn))
	v.refresh = time.Now().Add(time.Second * time.Duration(tokens.ExpiresIn/2))
	v.accesstoken = tokens.AccessToken
	return nil
}

func (v *ViCare) RefreshToken() error {
	// get refresh token
	if !v.HasRefreshToken() {
		return fmt.Errorf("No refresh token")
	}
	refreshToken, err := v.GetRefreshToken()
	if err != nil {
		return err
	}
	// set parameters for token request
	params := url.Values{}
	params.Set("client_id", v.clientId)
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", refreshToken)
	// prepare the request to token
	tokenrequest, err := http.NewRequest("POST", VICARE_TOKEN, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	tokenrequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// execute the query to token
	tokenresponse, err := v.client.Do(tokenrequest)
	if err != nil {
		return err
	}
	// check for error
	if tokenresponse.StatusCode/100 >= 4 {
		vicareerror := &Error{}
		json.NewDecoder(tokenresponse.Body).Decode(vicareerror)
		return fmt.Errorf(vicareerror.Error)
	}
	// read token response
	tokens := &TokenResponse{}
	json.NewDecoder(tokenresponse.Body).Decode(tokens)
	// set the expiry time
	err = v.SaveRefreshToken(tokens.RefreshToken)
	if err != nil {
		return fmt.Errorf("Could not save refresh token")
	}
	v.expires = time.Now().Add(time.Second * time.Duration(tokens.ExpiresIn))
	v.refresh = time.Now().Add(time.Second * time.Duration(tokens.ExpiresIn/2))
	v.accesstoken = tokens.AccessToken
	return nil
}

func (v *ViCare) GetInstalations() ([]Installation, error) {
	// check authentication
	err := v.AuthCheck()
	if err != nil {
		return nil, err
	}
	// basic request to instlations
	request, err := http.NewRequest("GET", fmt.Sprintf("%s%s", VICARE_BASE, "equipment/installations"), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.accesstoken))
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 >= 4 {
		vierror := &ViError{}
		err = json.NewDecoder(response.Body).Decode(&vierror)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(vierror.Message)
	}
	installResponse := InstalationResponse{}
	err = json.NewDecoder(response.Body).Decode(&installResponse)
	if err != nil {
		return nil, err
	}
	return installResponse.Data, nil
}

func (v *ViCare) GetGateways() ([]Gateway, error) {
	// check authentication
	err := v.AuthCheck()
	if err != nil {
		return nil, err
	}
	// basic request to instlations
	request, err := http.NewRequest("GET", fmt.Sprintf("%s%s", VICARE_BASE, "equipment/gateways"), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.accesstoken))
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 >= 4 {
		vierror := &ViError{}
		err = json.NewDecoder(response.Body).Decode(&vierror)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(vierror.Message)
	}
	/*body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	log.Printf("body: %s", body)*/
	gatewayResponse := GatewayResponse{}
	err = json.NewDecoder(response.Body).Decode(&gatewayResponse)
	if err != nil {
		return nil, err
	}
	return gatewayResponse.Data, nil
}

func (v *ViCare) GetDevices(installationId int, gatewaySerial string) ([]Device, error) {
	// check authentication
	err := v.AuthCheck()
	if err != nil {
		return nil, err
	}
	// basic request to instlations
	request, err := http.NewRequest("GET", fmt.Sprintf("%s%s", VICARE_BASE, fmt.Sprintf("equipment/installations/%d/gateways/%s/devices", installationId, gatewaySerial)), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.accesstoken))
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 >= 4 {
		vierror := &ViError{}
		err = json.NewDecoder(response.Body).Decode(&vierror)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(vierror.Message)
	}
	deviceResponse := DeviceResponse{}
	err = json.NewDecoder(response.Body).Decode(&deviceResponse)
	if err != nil {
		return nil, err
	}
	return deviceResponse.Data, nil
}

func (v *ViCare) GetFeatures(installationId int, gatewaySerial, deviceId string) ([]Feature, error) {
	// check authentication
	err := v.AuthCheck()
	if err != nil {
		return nil, err
	}
	// basic request to instlations
	request, err := http.NewRequest("GET", fmt.Sprintf("%s%s", VICARE_BASE, fmt.Sprintf("equipment/installations/%d/gateways/%s/devices/%s/features", installationId, gatewaySerial, deviceId)), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.accesstoken))
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 >= 4 {
		vierror := &ViError{}
		err = json.NewDecoder(response.Body).Decode(&vierror)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(vierror.Message)
	}
	featureResponse := FeatureResponse{}
	err = json.NewDecoder(response.Body).Decode(&featureResponse)
	if err != nil {
		return nil, err
	}
	return featureResponse.Data, nil
}

func (v *ViCare) GetFeaturesFiltered(installationId int, gatewaySerial, deviceId string, features []string) ([]Feature, error) {
	// check authentication
	err := v.AuthCheck()
	if err != nil {
		return nil, err
	}
	// basic request to instlations
	url := fmt.Sprintf("%s%s", VICARE_BASE, fmt.Sprintf("equipment/installations/%d/gateways/%s/devices/%s/features?filter=%s", installationId, gatewaySerial, deviceId, strings.Join(features, ",")))
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", v.accesstoken))
	response, err := v.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode/100 >= 4 {
		vierror := &ViError{}
		err = json.NewDecoder(response.Body).Decode(&vierror)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(vierror.Message)
	}
	featureResponse := FeatureResponse{}
	err = json.NewDecoder(response.Body).Decode(&featureResponse)
	if err != nil {
		return nil, err
	}
	return featureResponse.Data, nil
}

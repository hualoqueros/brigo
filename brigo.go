package brigo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type BRIConfig struct {
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
}

type BRICredentials struct {
	Token  string    `json:"access_token"`
	Config BRIConfig `json:"config"`
}

type Payload struct {
	Path      string `json:"path"`
	Verb      string `json:"verb"`
	Token     string `json:"token"`
	Timestamp string `json:"timestamp"`
	Body      string `json:"body`
}

func InitBRI(config BRIConfig) (briCred *BRICredentials, err error) {

	data := url.Values{}
	data.Set("client_id", config.ConsumerKey)
	data.Set("client_secret", config.ConsumerSecret)

	// GET TOKEN
	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, "https://sandbox.partner.api.bri.co.id/oauth/client_credential/accesstoken?grant_type=client_credentials", strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	res, _ := client.Do(r)
	if res.StatusCode >= 400 {
		log.Printf("ERROR Get token %+v", err)
		return &BRICredentials{}, err
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return &BRICredentials{}, err
	}

	err = json.Unmarshal(bodyBytes, &briCred)
	if err != nil {
		log.Printf("ERROR Unmarshal %+v", err)
		return &BRICredentials{}, err
	}

	return &BRICredentials{
		Token:  briCred.Token,
		Config: config,
	}, nil
}

func (bg *BRICredentials) CreateSignature(payload Payload) (signature string, err error) {

	secret := bg.Config.ConsumerSecret
	data := fmt.Sprintf(`path=%s&verb=%s&token=%s&timestamp=%s&body=%s`,
		payload.Path,
		payload.Verb,
		payload.Token,
		payload.Timestamp,
		payload.Body)

	// Get result and encode as hexadecimal string
	signature = ComputeHmac256(data, secret)

	return signature, err
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

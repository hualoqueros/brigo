package brigo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type EndPoint int

const (
	CreateVaURL EndPoint = iota
	CreateTokenURL
)

func (e EndPoint) String() string {
	return [...]string{"https://sandbox.partner.api.bri.co.id/v1/briva", "https://sandbox.partner.api.bri.co.id/oauth/client_credential/accesstoken?grant_type=client_credentials"}[e]
}

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

type ReqCreateBRIVA struct {
	InstitutionCode string  `json:"institutionCode"`
	BrivaNo         int     `json:"brivaNo"`
	CustCode        string  `json:"custCode"`
	Nama            string  `json:"nama"`
	Amount          float64 `json:"amount"`
	Keterangan      string  `json:"keterangan"`
	ExpiredDate     string  `json:"expiredDate"`
}

type ResCreateBRIVA struct {
}

func InitBRI(config BRIConfig) (briCred *BRICredentials, err error) {
	data := url.Values{}
	data.Set("client_id", config.ConsumerKey)
	data.Set("client_secret", config.ConsumerSecret)

	// GET TOKEN
	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, CreateTokenURL.String(), strings.NewReader(data.Encode())) // URL-encoded payload
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

func (bg *BRICredentials) CreateSignature(payload Payload) (signature string, timestamp time.Time, err error) {

	secret := bg.Config.ConsumerSecret
	data := fmt.Sprintf(`path=%s&verb=%s&token=%s&timestamp=%s&body=%s`,
		payload.Path,
		payload.Verb,
		payload.Token,
		payload.Timestamp,
		payload.Body)

	// Get result and encode as hexadecimal string
	signature = ComputeHmac256(data, secret)

	return signature, time.Now(), err
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (bg *BRICredentials) ParseEndpoint(method string, endpoint string, bodyRequest interface{}) (payload Payload, err error) {
	urlComponent, err := url.Parse(endpoint)
	if err != nil {
		return
	}

	body, _ := json.Marshal(bodyRequest)
	cleanBody, _ := strconv.Unquote(string(body))
	payload = Payload{
		Path:      urlComponent.Path,
		Verb:      "POST",
		Token:     "Bearer " + bg.Token,
		Timestamp: time.Now().Format("2006-01-02T15:04:05Z"),
		Body:      cleanBody,
	}

	return
}

func (bg *BRICredentials) CreateBRIVA(req ReqCreateBRIVA) (response map[string]interface{}, err error) {
	endpoint := CreateVaURL.String()
	body, _ := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	payload, err := bg.ParseEndpoint("POST", CreateVaURL.String(), string(body))
	if err != nil {
		return nil, err
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	buffPayload, _ := json.Marshal(payload)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buffPayload)) // URL-encoded payload
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("BRI-Timestamp", timestamp.Format("2006-01-02T15:04:05Z"))
	r.Header.Add("BRI-Signature", signature)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return nil, err
	}

	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		log.Printf("ERROR Unmarshal %+v", err)
		return nil, err
	}

	if status, ok := response["status"].(map[string]interface{}); ok {
		if errDesc, exists := status["desc"].(string); exists {
			return nil, errors.New(errDesc)
		}
	}

	return response, nil
}

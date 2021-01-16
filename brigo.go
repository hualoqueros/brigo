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
	GetVAStatusPaymentURL
)

func (e EndPoint) String() string {
	return [...]string{"https://sandbox.partner.api.bri.co.id/v1/briva", "https://sandbox.partner.api.bri.co.id/oauth/client_credential/accesstoken?grant_type=client_credentials", "https://sandbox.partner.api.bri.co.id/v1/briva/status/%s/%d/%s"}[e]
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
	Status              bool               `json:"status"`
	ResponseDescription string             `json:"responseDescription"`
	ResponseCode        string             `json:"responseCode"`
	Data                ResCreateBRIVAData `json:"data"`
}

type ResCreateBRIVAData struct {
	InstitutionCode string `json:"institutionCode"`
	BrivaNo         string `json:"brivaNo"`
	CustCode        string `json:"custCode"`
	Nama            string `json:"nama"`
	Amount          string `json:"amount"`
	Keterangan      string `json:"keterangan"`
	ExpiredDate     string `json:"expiredDate"`
}

type ReqGetBRIVAStatusPayment struct {
	InstitutionCode string `json:"institutionCode"`
	BrivaNo         int    `json:"brivaNo"`
	CustCode        string `json:"custCode"`
}

type ResGetBRIVAStatusPayment struct {
	Status              bool                         `json:"status"`
	ResponseDescription string                       `json:"responseDescription"`
	ResponseCode        string                       `json:"responseCode"`
	Data                ResGetBRIVAStatusPaymentData `json:"data"`
}

type ResGetBRIVAStatusPaymentData struct {
	Status string `json:"statusBayar"`
}

type RawResponse struct {
	Payload interface{}
}

type ErrorResponse struct {
	Status ErrorResponseData `json:"status`
}

type ErrorResponseData struct {
	Code        string `json:"code"`
	Description string `json:"desc"`
}

func (d *RawResponse) UnmarshalJSON(data []byte) error {
	var resp map[string]interface{}

	if err := json.Unmarshal(data, &resp); err != nil {
		log.Printf(err.Error(), "<<<< cek errornya")
		return err
	}

	if _, ok := resp["status"].(bool); ok {
		if _, isGetStatusVAPayment := resp["data"].(map[string]interface{})["statusBayar"]; isGetStatusVAPayment {
			d.Payload = new(ResGetBRIVAStatusPayment)
		} else {
			d.Payload = new(ResCreateBRIVAData)
		}
	} else {
		d.Payload = new(ErrorResponse)
	}
	return json.Unmarshal(data, d.Payload)

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
		Verb:      method,
		Token:     "Bearer " + bg.Token,
		Timestamp: time.Now().Format("2006-01-02T15:04:05Z"),
		Body:      cleanBody,
	}

	return
}

func (bg *BRICredentials) CreateBRIVA(req ReqCreateBRIVA) (response RawResponse, err error) {
	endpoint := CreateVaURL.String()
	log.Printf("\nendpoint => %+v", endpoint)
	body, _ := json.Marshal(req)
	if err != nil {
		return RawResponse{}, err
	}

	payload, err := bg.ParseEndpoint("POST", endpoint, string(body))
	if err != nil {
		return RawResponse{}, err
	}
	log.Printf("\npayload => %+v", payload)
	signature, timestamp, err := bg.CreateSignature(payload)
	log.Printf("\nsignature => %+v", signature)
	buffPayload, _ := json.Marshal(payload)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buffPayload)) // URL-encoded payload
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("BRI-Timestamp", timestamp.Format("2006-01-02T15:04:05Z"))
	r.Header.Add("BRI-Signature", signature)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return RawResponse{}, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return RawResponse{}, err
	}

	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		log.Printf("ERROR Unmarshal %+v", err)
		return RawResponse{}, err
	}

	switch response.Payload.(type) {
	case *ErrorResponse:
		result := response.Payload.(*ErrorResponse)
		err = errors.New(result.Status.Description)
		return response, err
	}

	return response, nil
}

func (bg *BRICredentials) GetVAStatusPayment(req ReqGetBRIVAStatusPayment) (response RawResponse, err error) {

	endpoint := fmt.Sprintf(GetVAStatusPaymentURL.String(), req.InstitutionCode, req.BrivaNo, req.CustCode)
	log.Printf("\nendpoint => %+v", endpoint)
	payload, err := bg.ParseEndpoint("GET", endpoint, nil)
	if err != nil {
		return RawResponse{}, err
	}
	log.Printf("\npayload => %+v", payload)
	signature, timestamp, err := bg.CreateSignature(payload)
	log.Printf("\nsignature => %+v", signature)
	buffPayload, _ := json.Marshal(payload)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, bytes.NewReader(buffPayload)) // URL-encoded payload
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("BRI-Timestamp", timestamp.Format("2006-01-02T15:04:05Z"))
	r.Header.Add("BRI-Signature", signature)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return RawResponse{}, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return RawResponse{}, err
	}

	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		log.Printf("ERROR Unmarshal %+v", err)
		return RawResponse{}, err
	}

	switch response.Payload.(type) {
	case *ErrorResponse:
		result := response.Payload.(*ErrorResponse)
		err = errors.New(result.Status.Description)
		return response, err
	}

	return response, nil
}

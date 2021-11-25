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

	"moul.io/http2curl"
)

type EndPoint int

const (
	CreateVaURL EndPoint = iota
	CreateTokenURL
	GetVAStatusPaymentURL
)

func (e EndPoint) String() string {
	return [...]string{"/v1/briva", "/oauth/client_credential/accesstoken?grant_type=client_credentials", "/v1/briva/status/%s/%d/%s"}[e]
}

type BRIConfig struct {
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	IsProd         bool   `json:"is_prod"`
	BaseURL        string `json:"base_url"`
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
	Body      string `json:"body"`
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

type ResCreateBRIVAError struct {
	Status              bool               `json:"status"`
	ResponseDescription string             `json:"errDesc"`
	ResponseCode        string             `json:"responseCode"`
	Data                ResCreateBRIVAData `json:"data"`
}

type ResCreateBRIVAData struct {
	InstitutionCode string `json:"institutionCode"`
	// BrivaNo         int     `json:"brivaNo"`
	CustCode    string  `json:"custCode"`
	Nama        string  `json:"nama"`
	Amount      float64 `json:"amount"`
	Keterangan  string  `json:"keterangan"`
	ExpiredDate string  `json:"expiredDate"`
}

type ReqGetBRIVAStatusPayment struct {
	InstitutionCode string `json:"institutionCode"`
	BrivaNo         int    `json:"brivaNo"`
	CustCode        string `json:"custCode"`
}
type ReqGetBRIVAReportPayment struct {
	InstitutionCode string `json:"institutionCode"`
	BrivaNo         int    `json:"brivaNo"`
	StartDate       string `json:"startDate"`
	EndDate         string `json:"endDate"`
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

type CreateBRIVAResponse struct {
	Status              bool               `json:"status"`
	ResponseDescription string             `json:"responseDescription"`
	ResponseCode        string             `json:"responseCode"`
	Data                ResCreateBRIVAData `json:"data"`
}

type FundTransferInternalRequest struct {
	Noreferral          string `json:"NoReferral"`
	Sourceaccount       string `json:"sourceAccount"`
	Beneficiaryaccount  string `json:"beneficiaryAccount"`
	Amount              string `json:"amount"`
	Feetype             string `json:"FeeType"`
	Transactiondatetime string `json:"transactionDateTime"`
	Remark              string `json:"remark"`
}

type FundTransferExternalRequest struct {
	Noreferral             string `json:"NoReferral"`
	BankCode               string `json:"bankCode"`
	Sourceaccount          string `json:"sourceAccount"`
	Beneficiaryaccount     string `json:"beneficiaryAccount"`
	BeneficiaryAccountName string `json:"beneficiaryAccountName"`
	Amount                 string `json:"amount"`
}

func (d *RawResponse) UnmarshalJSON(data []byte) error {
	var resp map[string]interface{}

	if err := json.Unmarshal(data, &resp); err != nil {
		log.Printf(err.Error(), "<<<< cek errornya")
		return err
	}

	if status, ok := resp["status"].(bool); ok && status == true {
		if _, isGetStatusVAPayment := resp["data"].(map[string]interface{})["statusBayar"]; isGetStatusVAPayment {
			d.Payload = new(ResGetBRIVAStatusPayment)
		} else {
			d.Payload = new(ResCreateBRIVA)
		}
	} else {
		if _, errorDescription := resp["errDesc"].(string); errorDescription {
			d.Payload = new(ResCreateBRIVAError)
		} else {
			d.Payload = new(ErrorResponse)
		}

	}
	return json.Unmarshal(data, d.Payload)

}

func InitBRI(config BRIConfig) (briCred *BRICredentials, err error) {

	data := url.Values{}
	data.Set("client_id", config.ConsumerKey)
	data.Set("client_secret", config.ConsumerSecret)

	if config.IsProd {
		config.BaseURL = "https://partner.api.bri.co.id"
	} else {
		config.BaseURL = "https://sandbox.partner.api.bri.co.id"
	}

	// GET TOKEN
	client := &http.Client{}
	r, err := http.NewRequest(http.MethodPost, config.BaseURL+CreateTokenURL.String(), strings.NewReader(data.Encode())) // URL-encoded payload
	if err != nil {
		log.Printf("ERROR NewRequest %+v", err)
		return &BRICredentials{}, err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	res, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR hit api %+v", err)
		return &BRICredentials{}, err
	}
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

func (bg *BRICredentials) CreateSignature(payload Payload) (signature string, timestamp string, err error) {

	secret := bg.Config.ConsumerSecret

	data := fmt.Sprintf(`path=%s&verb=%s&token=%s&timestamp=%s&body=%s`,
		payload.Path,
		payload.Verb,
		payload.Token,
		payload.Timestamp,
		payload.Body)

	// fmt.Println(data)
	// fmt.Println(secret)
	// Get result and encode as hexadecimal string
	signature = ComputeHmac256(data, secret)

	// fmt.Println(signature)
	return signature, payload.Timestamp, err
}

func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (bg *BRICredentials) ParseEndpoint(method string, endpoint string, bodyRequest interface{}, timeNow time.Time) (payload Payload, err error) {
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
		Timestamp: timeNow.Format("2006-01-02T15:04:05.000Z"),
		Body:      cleanBody,
	}
	return
}

func (bg *BRICredentials) CreateBRIVA(req ReqCreateBRIVA) (result CreateBRIVAResponse, err error) {
	var response RawResponse
	endpoint := bg.Config.BaseURL + CreateVaURL.String()
	body, _ := json.Marshal(req)
	if err != nil {
		return CreateBRIVAResponse{}, err
	}
	timeNow := time.Now().UTC()

	payload, err := bg.ParseEndpoint("POST", endpoint, string(body), timeNow)
	if err != nil {
		return CreateBRIVAResponse{}, err
	}
	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR CreateSignature %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, endpoint, buffPayload)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("BRI-Timestamp", timestamp)
	r.Header.Set("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	command, _ := http2curl.GetCurlCommand(r)
	fmt.Printf("CURL => %+v", command)

	// HIT
	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return CreateBRIVAResponse{}, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return CreateBRIVAResponse{}, err
	}

	fmt.Println(string(bodyBytes))

	err = json.Unmarshal(bodyBytes, &response)
	if err != nil {
		log.Printf("ERROR Unmarshal %+v", err)
		return CreateBRIVAResponse{}, err
	}

	switch response.Payload.(type) {
	case *ErrorResponse:
		res := response.Payload.(*ErrorResponse)
		result = CreateBRIVAResponse{
			Status:              false,
			ResponseDescription: res.Status.Description,
			ResponseCode:        res.Status.Code,
		}
		err = errors.New(res.Status.Description)
	case *ResCreateBRIVA:
		log.Printf("SUCCESS => %+v", response)
		res := response.Payload.(*ResCreateBRIVA)
		result = CreateBRIVAResponse{
			Status:              res.Status,
			ResponseDescription: res.ResponseDescription,
			ResponseCode:        res.ResponseCode,
			Data:                res.Data,
		}
	case *ResCreateBRIVAError:
		res := response.Payload.(*ResCreateBRIVAError)
		result = CreateBRIVAResponse{
			Status:              res.Status,
			ResponseDescription: res.ResponseDescription,
			ResponseCode:        res.ResponseCode,
			Data:                res.Data,
		}
	}

	return result, nil
}

func (bg *BRICredentials) GetVAStatusPayment(req ReqGetBRIVAStatusPayment) (response RawResponse, err error) {

	endpoint := fmt.Sprintf(bg.Config.BaseURL+GetVAStatusPaymentURL.String(), req.InstitutionCode, req.BrivaNo, req.CustCode)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return RawResponse{}, err
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

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

func (bg *BRICredentials) FundTransferAccountValidation(sourceAccount string, beneficiaryAccount string) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v3/transfer/internal/accounts?sourceaccount=%s&beneficiaryaccount=%s"
	endpoint := fmt.Sprintf(url, sourceAccount, beneficiaryAccount)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) FundTransferExternalAccountValidation(bankCode string, beneficiaryAccount string) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v2/transfer/external/accounts?bankcode=%s&beneficiaryaccount=%s"
	endpoint := fmt.Sprintf(url, bankCode, beneficiaryAccount)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) FundTransferCheckStatus(noReferral string) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v3/transfer/internal?noreferral=%s"
	endpoint := fmt.Sprintf(url, noReferral)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) FundTransfereExternalCheckStatus(noReferral string) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v3/transfer/external/accounts?noreferral=%s"
	endpoint := fmt.Sprintf(url, noReferral)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) FundTransferInternal(req FundTransferInternalRequest) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v3/transfer/internal"
	endpoint := fmt.Sprintf(url)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	body, _ := json.Marshal(req)
	if err != nil {
		return
	}

	payload, err := bg.ParseEndpoint("POST", endpoint, string(body), timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)
	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)
	r.Header.Set("Content-Type", "application/json")

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) FundTransferExternal(req FundTransferExternalRequest) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v2/transfer/external"
	endpoint := fmt.Sprintf(url)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	body, _ := json.Marshal(req)
	if err != nil {
		return
	}

	payload, err := bg.ParseEndpoint("POST", endpoint, string(body), timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)
	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodPost, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)
	r.Header.Set("Content-Type", "application/json")

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return
}

func (bg *BRICredentials) GetBankCode() (response []byte, err error) {

	endpoint := fmt.Sprintf(bg.Config.BaseURL + "/v2/transfer/external/accounts")
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return
	}

	return response, nil
}

func (bg *BRICredentials) GetVAReportPayment(req ReqGetBRIVAReportPayment) (response []byte, err error) {
	url := bg.Config.BaseURL + "/v1/briva/report/%s/%d/%s/%s"
	endpoint := fmt.Sprintf(url, req.InstitutionCode, req.BrivaNo, req.StartDate, req.EndDate)
	// log.Printf("\nendpoint => %+v", endpoint)
	timeNow := time.Now().UTC()
	payload, err := bg.ParseEndpoint("GET", endpoint, nil, timeNow)
	if err != nil {
		return response, err
	}

	signature, timestamp, err := bg.CreateSignature(payload)
	if err != nil {
		log.Printf("ERROR buffPayload %+v", err)
	}
	bd := []byte(payload.Body)
	buffPayload := bytes.NewReader(bd)

	client := &http.Client{}
	r, _ := http.NewRequest(http.MethodGet, endpoint, buffPayload) // URL-encoded payload
	r.Header.Add("BRI-Timestamp", timestamp)
	r.Header.Add("BRI-Signature", signature)
	bearerToken := "Bearer " + bg.Token
	r.Header.Set("Authorization", bearerToken)

	// command, _ := http2curl.GetCurlCommand(r)
	// fmt.Printf("CURL => %+v", command)

	resp, err := client.Do(r)
	if err != nil {
		log.Printf("ERROR REQUEST %+v", err)
		return response, err
	}

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ERROR ReadResponse %+v", err)
		return response, err
	}

	// err = json.Unmarshal(bodyBytes, &response)
	// if err != nil {
	// 	log.Printf("ERROR Unmarshal %+v", err)
	// 	return RawResponse{}, err
	// }

	// switch response.Payload.(type) {
	// case *ErrorResponse:
	// 	result := response.Payload.(*ErrorResponse)
	// 	err = errors.New(result.Status.Description)
	// 	return response, err
	// }

	return response, nil
}

package brigo

import (
	"encoding/json"
	"testing"
	"time"
)

func TestGetToken(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}

	briInit, err := InitBRI(briConfig)

	if err != nil {
		t.Error("\nSALAH!")
	}

	t.Logf("\nBERHASIL : %+v", briInit)

}

func TestCreateSignature(t *testing.T) {
	endpoint := "https://sandbox.partner.api.bri.co.id/v1/briva"

	briConfig := BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}

	bri, err := InitBRI(briConfig)
	if err != nil {
		t.Errorf("\nSALAH! = %+v", err)
	}

	expiredDate := time.Now().AddDate(0, 1, 0).Format("2006-01-02 15:04:05")
	bodyStruct := ReqCreateBRIVA{
		InstitutionCode: "J104408",
		BrivaNo:         77777,
		CustCode:        "123456789115",
		Nama:            "Sabrina",
		Amount:          100000,
		Keterangan:      "BRIVA Testing",
		ExpiredDate:     expiredDate,
	}

	body, _ := json.Marshal(bodyStruct)
	payload, err := bri.ParseEndpoint("POST", endpoint, string(body))
	if err != nil {
		t.Errorf("\nSALAH! = %+v", err)
	}

	signature, _, err := bri.CreateSignature(payload)
	if err != nil {
		t.Errorf("\nSALAH! = %+v", err)
	}

	t.Logf("\nBERHASIL : %+v", signature)
}

func TestCreateVirtualAccount(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}

	bri, err := InitBRI(briConfig)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	expiredDate := time.Now().AddDate(0, 1, 0).Format("2006-01-02 15:04:05")
	reqCreateBRIVA := ReqCreateBRIVA{
		InstitutionCode: "J104408",
		BrivaNo:         77777,
		CustCode:        "123456789115",
		Nama:            "Sabrina",
		Amount:          100000,
		Keterangan:      "BRIVA Testing",
		ExpiredDate:     expiredDate,
	}

	response, err := bri.CreateBRIVA(reqCreateBRIVA)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	t.Logf("\nSuccess = %+v", response.Payload)
}

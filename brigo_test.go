package brigo

import (
	"testing"
	"time"
)

/**
func TestGetToken(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "S0kEtZNkGunQvuMuEWmsC68De5wuzfDA",
		ConsumerSecret: "feI8fGussIwJGOWj",
	}

	briInit, err := InitBRI(briConfig)

	if err != nil {
		t.Error("\nSALAH!")
	}

	t.Logf("\nBERHASIL : %+v", briInit)

}
**/
/**
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
	t.Logf("\nToken = %+v", bri.Token)

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
	timeNow := time.Now()
	payload, err := bri.ParseEndpoint("POST", endpoint, string(body), timeNow)
	if err != nil {
		t.Errorf("\nSALAH! = %+v", err)
	}

	signature, _, err := bri.CreateSignature(payload)
	if err != nil {
		t.Errorf("\nSALAH! = %+v", err)
	}

	t.Logf("\nBERHASIL : %+v", signature)
}
**/

func TestCreateVirtualAccount(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "S0kEtZNkGunQvuMuEWmsC68De5wuzfDA",
		ConsumerSecret: "feI8fGussIwJGOWj",
	}

	bri, err := InitBRI(briConfig)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	expiredDate := time.Now().UTC().AddDate(0, 1, 0).Format("2006-01-02 15:04:05")
	reqCreateBRIVA := ReqCreateBRIVA{
		InstitutionCode: "J104408",
		BrivaNo:         77777,
		CustCode:        "441223176",
		Nama:            "Sabrina",
		Amount:          100000,
		Keterangan:      "BRIVA Testing",
		ExpiredDate:     expiredDate,
		// ExpiredDate: "2021-07-02 17:29:04",
	}

	response, err := bri.CreateBRIVA(reqCreateBRIVA)
	// t.Errorf("Response => %+v", response.Payload)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	// t.Errorf("\nResult Type = %T", response)
	// t.Errorf("\nResult = %+v", response)
	if !response.Status {
		t.Errorf("\nERROR = %+v", response)
	}
	t.Logf("\nResult = %+v", response)
}

/**
func TestGetVirtualAccountStatusPayment(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "S0kEtZNkGunQvuMuEWmsC68De5wuzfDA",
		ConsumerSecret: "feI8fGussIwJGOWj",
	}

	bri, err := InitBRI(briConfig)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	reqGetBRIVAStatusPayment := ReqGetBRIVAStatusPayment{
		InstitutionCode: "J104408",
		BrivaNo:         77777,
		CustCode:        "123456789115",
	}

	response, err := bri.GetVAStatusPayment(reqGetBRIVAStatusPayment)
	if err != nil {
		t.Errorf("\nError = %+v", err)
		return
	}

	t.Logf("\nSuccess = %+v", response.Payload)
}
**/

package brigo

import (
	"encoding/json"
	"testing"
)

func TestGetToken(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}

	briInit, err := InitBRI(briConfig)

	if err != nil {
		t.Error("SALAH!")
	}

	t.Logf("BERHASIL : %+v", briInit)

}

func TestSignature(t *testing.T) {

	briConfig := BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}

	bri, err := InitBRI(briConfig)
	timestamp := "2019-01-02T13:14:15.678Z"
	bodyStruct := map[string]interface{}{
		"hello": "world",
	}
	body, _ := json.Marshal(bodyStruct)

	payload := Payload{
		Path:      "/v1/transfer/internal",
		Verb:      "POST",
		Token:     "Bearer " + bri.Token,
		Timestamp: timestamp,
		Body:      string(body),
	}
	signature, err := bri.CreateSignature(payload)
	if err != nil {
		t.Errorf("SALAH! = %+v", err)
	}

	t.Logf("BERHASIL : %+v", signature)

}

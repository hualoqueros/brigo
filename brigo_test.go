package brigo

import (
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

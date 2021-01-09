# brigo
This is golang sdk for consume BRI (Bank Rakyat Indonesia) API https://developers.bri.co.id/



### How to use



```go
package main

import "https://github.com/hualoqueros/brigo"

func main() {
  // fill this with your credentials
  briConfig := brigo.BRIConfig{
		ConsumerKey:    "E4Ar8prAnXGKO7S6lPTqJWVcOKZqzN1G",
		ConsumerSecret: "M8YgS30WASAkbaZU",
	}
  
  // initialize 
  bri, err := brigo.InitBRI(briConfig)
}
```

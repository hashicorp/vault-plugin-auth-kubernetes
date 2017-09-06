package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const configLocation string = "/etc/example-app/config.json"

type config struct {
	Secret string `json:"secret"`
}

func main() {
	config, err := getConfig()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(config)
}

func getConfig() (*config, error) {
	for {
		content, err := ioutil.ReadFile(configLocation)
		switch {
		case os.IsNotExist(err):
			time.Sleep(5 * time.Millisecond)
			continue
		case err != nil:
			return nil, err
		}

		var config *config
		err = json.Unmarshal(content, config)
		if err != nil {
			return nil, err
		}

		return config, nil
	}
}

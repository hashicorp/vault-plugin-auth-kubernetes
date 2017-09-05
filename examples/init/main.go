package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
)

func main() {
	if os.Getenv("VAULT_TOKEN") != "" {
		fmt.Println(os.Getenv("VAULT_TOKEN"))
	}

	config := api.DefaultConfig()
	vaultClient, err := api.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	s, err := vaultClient.Logical().Write("/auth/kube/login", map[string]interface{}{
		"role": "dev",
		"jwt":  "",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(s.Auth.ClientToken)
}

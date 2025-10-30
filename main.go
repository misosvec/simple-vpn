package main

import (
	"fmt"
	"vpn/common"
)

func main() {
	pt := []byte("this is my plaintext motherfuckerthis is my plaintext motherfuckerthis is my plaintext motherfuckerthis is my plaintext motherfuckerthis is my plaintext motherfucker")
	key := common.GenerateKey()
	encrypted := common.Encrypt(pt, key)
	fmt.Println(string(encrypted))
}

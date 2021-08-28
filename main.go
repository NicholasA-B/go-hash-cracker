package main

import (
	"fmt"
	"os"
	"strconv"
	"github.com/NicholasA-B/go-hash-cracker/pass"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("usage: ./go-hash-cracker hash_file use_salt wordlist")
		fmt.Println("example: ./go-hash-cracker hash.txt false top-10000-passwords.txt")
		os.Exit(1)
	}
	
	hashFile := os.Args[1]
	useSalts, _ := strconv.ParseBool(os.Args[2])
	passwordList := os.Args[3]
	hash := pass.ReadHash(hashFile)
	
	if hash == "1" {
		os.Exit(1)
	}
	
	str := pass.CrackSha1Hash(hash, useSalts, passwordList)
	fmt.Println(str)
}
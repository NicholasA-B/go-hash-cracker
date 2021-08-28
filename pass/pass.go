package pass

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"strings"
	"regexp"
)

func readInPasswords(passwordList string) []string {
	b, err := ioutil.ReadFile(passwordList)
	if err != nil {
		fmt.Println(err)
	}
	str := string(b)
	return strings.Split(str, "\n")
}

func readInSalts() []string {
	b, err := ioutil.ReadFile("known-salts.txt")
	if err != nil {
		fmt.Println(err)
	}
	str := string(b)
	return strings.Split(str, "\n")
}

func hashString(str string) string {
	bs :=sha1.Sum([]byte(str))
	return fmt.Sprintf("%x", bs)
}

func hashWithSalts(str string) []string {
	var s []string
	for _, salt := range readInSalts() {
		s = append(s, hashString(str+salt))
		s = append(s, hashString(salt+str))
	}
	return s
}

func ReadHash(str string) string {
	b, err := ioutil.ReadFile(str)
	if err != nil {
		fmt.Println(err)
	}
	isHash := validateHash(string(b))
	if isHash == true {
		return string(b)
	} else {
		return "1"
	}
}

func validateHash(str string) bool {
	matched, _ := regexp.MatchString(`^[a-z0-9]{40}$`, str)
	if matched {
		return true
	} else {
		fmt.Println("NOT A VALID SHA-1 HASH")
		return false
	}
}

func CrackSha1Hash(str string, useSalt bool, passwordList string) string {
	for _, pass := range readInPasswords(passwordList) {
		if useSalt {
			for _, salted := range hashWithSalts(pass) {
				if salted == str {
					return pass
				}	
			}
		} else if hashString(pass) == str {
			return pass
		}
	}
	return "PASSWORD NOT IN DATABASE"
}
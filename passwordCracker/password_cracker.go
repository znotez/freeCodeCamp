package passwordCracker

import (
	"crypto/sha1"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

const NOTFOUND = "PASSWORD NOT IN DATABASE"

func readFileByLine(filename string) ([]string, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return []string{}, err
	}
	return strings.Split(string(b), "\n"), nil
}

func hashString(str string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(str)))
}

func saltPwds(str string) []string {
	var saltPwds []string
	salts, err := readFileByLine("./known-salts.txt")
	if err != nil {
		return []string{}
	}
	for _, salt := range salts {
		saltPwds = append(saltPwds, str+salt)
		saltPwds = append(saltPwds, salt+str)
	}
	return saltPwds
}

func CheckSha1Hash(hash string, use_salts ...bool) string {
	passwords, err := readFileByLine("./top-10000-passwords.txt")
	if err != nil {
		log.Fatalln("can't read ./top-10000-passwords.txt")
	}
	if len(use_salts) == 0 || len(use_salts) > 0 && use_salts[0] == false {
		for _, pass := range passwords {
			if hashString(pass) == hash {
				return pass
			}
		}
	} else {
		for _, pass := range passwords {
			for _, saltpass := range saltPwds(pass) {
				if hashString(saltpass) == hash {
					return pass
				}
			}
		}
	}
	return NOTFOUND
}

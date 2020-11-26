package main

import (
	"log"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	config := &PasswordConfig{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}

	full, hash, err := GeneratePassword(config, "password123")
	if err != nil {
		log.Fatal(err)
	}
	if len(full) != 97 {
		t.Errorf("Generated password length incorrect")
	} else {
		t.Logf("Generated password length correct")
	}
	if len(hash) != 32 {
		t.Errorf("Generated hash length incorrect")
	}
}

func TestComparePasswordGood(t *testing.T) {
	match, err := ComparePassword("password123", "$argon2id$v=19$m=65536,t=1,p=4$a9dPXnFOP30MXgXlPtod8g$AMU/PomFPbOLrjof9ALIBRlKqaq/S4qfwMhkcEsJf74")
	if !match || err != nil {
		t.Errorf("Known good password found found invalid")
	} else {
		t.Logf("Known good password found valid")
	}
}

func TestComparePasswordBad(t *testing.T) {
	match, err := ComparePassword("Password", "$argon2id$v=19$m=65536,t=1,p=4$a9dPXnFOP30MXgXlPtod8g$AMU/PomFPbOLrjof9ALIBRlKqaq/S4qfwMhkcEsJf74")
	if !match || err != nil {
		t.Logf("Known bad password found found invalid")
	} else {
		t.Errorf("Known bad password found valid")
	}
}

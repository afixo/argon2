package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type argon2Data struct {
	algoType string
	version  int
	memory   int
	times    int
	threads  int
	salt     string
	hash     string
}

func HashPassword(password []byte) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	algo := "argon2id"
	threads := uint8(4)
	time := uint32(10)
	memory := uint32(32 * 1024)

	hash := argon2.IDKey(password, salt, time, memory, threads, 32)

	b64Hash := base64.StdEncoding.EncodeToString(hash)
	b64Salt := base64.StdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", algo, argon2.Version, memory, time, threads, b64Salt, b64Hash), nil
}

func HashPasswordWSettings(password []byte, salt []byte, algo string, time,
	memory uint32, threads uint8, keyLength uint32) string {
	var hash []byte
	switch algo {
	case "argon2id":
		hash = argon2.IDKey(password, salt, time, memory, threads, keyLength)
		break
	case "argon2i":
		hash = argon2.Key(password, salt, time, memory, threads, keyLength)
		break
	}

	b64Hash := base64.StdEncoding.EncodeToString(hash)
	b64Salt := base64.StdEncoding.EncodeToString(salt)

	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s", algo, argon2.Version, memory, time, threads, b64Salt, b64Hash)
}

func generateSalt() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return b, err
	}
	return b, nil
}

func Compare(encodedHash string, password []byte) (bool, error) {
	data, err := split(encodedHash)
	if err != nil {
		return false, err
	}

	salt, err := base64.StdEncoding.DecodeString(data.salt)
	if err != nil {
		return false, err
	}

	savedHash, err := base64.StdEncoding.DecodeString(data.hash)
	if err != nil {
		return false, err
	}

	encoded := HashPasswordWSettings(password, salt, "argon2id",
		uint32(data.times), uint32(data.memory), uint8(data.threads),
		uint32(len(savedHash)))

	return subtle.ConstantTimeCompare([]byte(encoded),
		[]byte(encodedHash)) == 1, nil
}

func split(encoded string) (*argon2Data, error) {
	parts := make([]string, 0)
	splits := strings.SplitAfter(encoded, "$")
	splits = splits[1:]
	for _, v := range splits {
		parts = append(parts, strings.TrimSuffix(v, "$"))
	}

	versionStr := strings.Split(parts[1], "=")[1]
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return nil, err
	}

	parameters := strings.Split(parts[2], ",")

	memStr := strings.Split(parameters[0], "=")[1]
	mem, err := strconv.Atoi(memStr)
	if err != nil {
		return nil, err
	}

	timesStr := strings.Split(parameters[1], "=")[1]
	times, err := strconv.Atoi(timesStr)
	if err != nil {
		return nil, err
	}

	threadsStr := strings.Split(parameters[2], "=")[1]
	threads, err := strconv.Atoi(threadsStr)
	if err != nil {
		return nil, err
	}

	data := argon2Data{
		algoType: parts[0],
		version:  version,
		memory:   mem,
		times:    times,
		threads:  threads,
		salt:     parts[3],
		hash:     parts[4],
	}

	return &data, nil
}

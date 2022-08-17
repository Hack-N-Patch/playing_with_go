package hashcrack

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
)

func StringToMd5(plain string) string {
	data := []byte(plain)
	md5sum := fmt.Sprintf("%x", md5.Sum(data))

	return md5sum
}

func StringToSha256(plain string) string {
	data := []byte(plain)
	sha256sum := fmt.Sprintf("%x", sha256.Sum256(data))

	return sha256sum
}

func CompareMd5(word, crackme string) {
	if StringToMd5(word) == crackme {
		fmt.Printf("[+] Cracked!\n%s == %s\n", word, crackme)
		os.Exit(0)
	}
}

func CompareSha256(word, crackme string) {
	if StringToSha256(word) == crackme {
		fmt.Printf("[+] Cracked!\n%s == %s\n", word, crackme)
		os.Exit(0)
	}
}

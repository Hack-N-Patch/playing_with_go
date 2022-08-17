package main

import (
	"bufio"
	"flag"
	"fmt"
	"hashcrack"
	"os"
	"strings"
)

func main() {
	// parse CLI for hash value, hash type, and wordlist
	hashPtr := flag.String("hash", "", "hash value to crack")
	hashtypePtr := flag.String("type", "md5", "hash type, defaults to md5, supports md5 OR sha256")
	wordlistPtr := flag.String("wordlist", "", "path to plaintext wordlist for cracking")
	flag.Parse()

	crackme := *hashPtr
	// check for empty hash value
	if crackme == "" {
		fmt.Println("No hash value provided. Exiting...")
		os.Exit(1)
	}
	hashtype := strings.ToLower(*hashtypePtr)
	wordlist_path := *wordlistPtr

	// Open File
	wordlist, err := os.Open(wordlist_path)

	if err != nil {
		fmt.Println("Failed to open worldlist. Exiting...")
		os.Exit(1)
	}
	defer wordlist.Close()

	// Iterate through strings in file, calculate, and compare hash
	fileScanner := bufio.NewScanner(wordlist)
	fileScanner.Split(bufio.ScanLines)

	if hashtype == "md5" {
		fmt.Println("[+] Cracking MD5...")
		for fileScanner.Scan() {
			// the work completes so quickly goroutines didn't speed up
			// time required to crack during testing
			hashcrack.CompareMd5(fileScanner.Text(), crackme)
		}
	} else if hashtype == "sha256" {
		fmt.Println("[+] Cracking SHA256...")
		for fileScanner.Scan() {
			// the work completes so quickly goroutines didn't speed up
			// time required to crack during testing
			hashcrack.CompareSha256(fileScanner.Text(), crackme)
		}
	} else {
		fmt.Println("Algorithm unsupported. Exiting...")
		os.Exit(1)
	}

	fmt.Println("[-] Unable to crack :-(")
}

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// checks for an error and prints to the console if found
func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

// queries the Shodan API, prints OS, tags, domains, listening ports
func shodanIpInfo(ip string) {
	SHODAN_API := os.Getenv("SHODAN_API")
	if SHODAN_API == "" {
		fmt.Println("SHODAN_API environment variable not found")
		return
	}

	// prepare the URL for the request
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, SHODAN_API)

	// hit the API endpoint, check for errors
	resp, err := http.Get(url)
	check(err)
	defer resp.Body.Close()

	// retrieve and parse response data
	body, _ := ioutil.ReadAll(resp.Body)
	var dat map[string]interface{}
	err = json.Unmarshal([]byte(body), &dat)
	check(err)

	// display output
	if resp.StatusCode == 200 {
		operating_system := fmt.Sprintf("%s", dat["os"])
		domains := fmt.Sprintf("%s", dat["domains"])
		tags := fmt.Sprintf("%s", dat["tags"])

		if operating_system != "%!s(<nil>)" {
			fmt.Println("Operating System:", operating_system)
		}

		if tags != "[]" {
			fmt.Println("Tagged as:", tags)
		}

		if domains != "[]" {
			fmt.Println("Hosts domains:", domains)
		}

		fmt.Println("Listening on ports:", dat["ports"])

	} else {
		fmt.Println("Shodan says...", dat["error"])
	}

	fmt.Println()
}

// queries the GreyNoise (Community) API, prints name, classification, common business service, background noise
func greynoiseIpInfo(ip string) {
	GREYNOISE_API := os.Getenv("GREYNOISE_API")
	if GREYNOISE_API == "" {
		fmt.Println("GREYNOISE_API environment variable not found")
		return
	}

	// prepare and make HTTP request
	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	// The enterprise API gives more info https://api.greynoise.io/v2/noise/context/{ip}
	req, err := http.NewRequest("GET", url, nil)
	check(err)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("key", GREYNOISE_API)
	resp, err := http.DefaultClient.Do(req)
	check(err)
	defer resp.Body.Close()

	// retrieve and parse response data
	body, _ := ioutil.ReadAll(resp.Body)
	var dat map[string]interface{}
	err = json.Unmarshal([]byte(body), &dat)
	check(err)

	if dat["message"] == "Success" {
		//fmt.Println("Here's what GreyNoise knows about the IP...")
		//fmt.Println(string(body))
		fmt.Println("Name:", dat["name"])
		fmt.Println("Classification:", dat["classification"])
		fmt.Println("Common Business Service:", dat["riot"])
		fmt.Println("Internet Background Noise:", dat["noise"])
	} else {
		fmt.Println("GreyNoise says...", dat["message"])
	}

}

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("Usage: \t\t%s <ip address>\n", os.Args[0])
		fmt.Printf("Example: \t%s 8.8.8.8\n", os.Args[0])
		os.Exit(1)
	}
	ip := os.Args[1]

	greynoiseIpInfo(ip)
	shodanIpInfo(ip)

}

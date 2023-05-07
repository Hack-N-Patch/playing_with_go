package internal

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/blacktop/go-macho"
	"github.com/h2non/filetype"
	"go.mozilla.org/pkcs7"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sync"
)

type AnalyzedFile struct {
	// if the field name is plural, expect a slice
	Md5          string
	Sha1         string
	Sha256       string
	MIMEType     string
	IsValidMacho bool
	IsDylib      bool
	VTPositive   int
	VTTotal      int
	Strings      []string
	SectionNames []string
	Imports      []string
	Exports      []string
	Symbols      []string
	Signatures   []string
	Insights     []string
}

func GetHashes(f []byte) (string, string, string) {
	hashMD5 := md5.Sum(f)
	md5 := hex.EncodeToString(hashMD5[:])
	hashSHA1 := sha1.Sum(f)
	sha1 := hex.EncodeToString(hashSHA1[:])
	hashSHA256 := sha256.Sum256(f)
	sha256 := hex.EncodeToString(hashSHA256[:])
	return md5, sha1, sha256
}

func CheckVirusTotal(hash string) (int, int) {
	// short circuit to save on API calls while testing
	// fmt.Println("FYI VTCheck is short circuitted")
	// return 0, 60
	type reputation struct {
		Positives int `json:"positives"`
		Total     int `json:"total"`
	}

	VTAPI := os.Getenv("VTAPI")
	if VTAPI == "" {
		return -1, -1
	}
	url := "https://www.virustotal.com/vtapi/v2/file/report?apikey=" + VTAPI + "&resource=" + hash + "&allinfo=false"

	r, err := http.Get(url)
	if err != nil {
		panic(err)
	}

	if r.StatusCode == http.StatusOK {
		data, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		var rep reputation
		err = json.Unmarshal(data, &rep)
		if err != nil {
			panic(err)
		}

		return rep.Positives, rep.Total
	} else if r.StatusCode == 204 {
		return -2, -2
	} else {
		fmt.Println(r.Status)
	}

	return -3, -3
}

func GetAsciiStrings(f []byte) []string {
	var result []string

	// iterate through each byte
	for i := 0; i < len(f); i++ {
		// if the character is in the ascii range...
		if f[i] >= 32 && f[i] <= 126 {
			// iterate through the next character to see if it's in the ascii range too
			j := i + 1
			for j < len(f) && f[j] >= 32 && f[j] <= 126 {
				j++
			}
			// only append the string if the sequence is greater than 5 characters
			if j-i > 5 {
				result = append(result, string(f[i:j]))
			}
			// jump ahead to the end of the newly created string
			i = j
		}
	}

	/* go-go-gadget deduplication
	dedup := map[string]struct{}{}
	count := 0
	for _, v := range result {
		if _, exists := dedup[v]; !exists {
			dedup[v] = struct{}{}
			result[count] = v
			count++
		}
	}
	result = result[:count]*/

	return stringDedup(result)
}

func stringDedup(data []string) []string {
	dedup := map[string]struct{}{}
	count := 0
	for _, v := range data {
		if _, exists := dedup[v]; !exists {
			dedup[v] = struct{}{}
			data[count] = v
			count++
		}
	}
	data = data[:count]

	return data
}

func DetermineFileType(f []byte) string {
	// APP files as folders
	// PKG file types are treated as folders
	// Read the first 512 bytes of the file to determine its type
	kind, err := filetype.Match(f)
	if err != nil {
		fmt.Println("Error", err)
		return ""
	}
	return kind.MIME.Value
}

func GetDigitalSignatures(arch macho.FatArch) []string {
	var sigs []string
	var sigBlob []byte

	// this catches errors from trying to access CMSSignature if CodeSignature doesn't exist
	if arch.CodeSignature() != nil {
		sigBlob = arch.CodeSignature().CMSSignature
	} else {
		// no code signature
		return sigs
	}

	sigData, err := pkcs7.Parse(sigBlob)
	if err != nil {
		fmt.Println(err)
	}

	if sigData != nil {
		for _, signers := range sigData.Certificates {
			sigs = append(sigs, signers.Subject.CommonName)
		}
	}

	return sigs
}

func GetDigitalSignaturesSlim(arch *macho.File) []string {
	var sigs []string
	var sigBlob []byte

	// this catches errors from trying to access CMSSignature if CodeSignature doesn't exist
	if arch.CodeSignature() != nil {
		sigBlob = arch.CodeSignature().CMSSignature
	} else {
		// no code signature
		return sigs
	}

	sigData, err := pkcs7.Parse(sigBlob)
	if err != nil {
		fmt.Println(err)
	}

	if sigData != nil {
		for _, signers := range sigData.Certificates {
			sigs = append(sigs, signers.Subject.CommonName)
		}
	}
	return sigs
}

func GetSectionNames(arch macho.FatArch) []string {
	var result []string
	for _, v := range arch.Sections {
		result = append(result, v.Name)
	}
	return result
}

func GetSectionNamesSlim(arch *macho.File) []string {
	var result []string
	for _, v := range arch.Sections {
		result = append(result, v.Name)
	}
	return result
}

func GetMachOImportedSymbols(arch macho.FatArch) []string {
	syms, err := arch.ImportedSymbols()
	if err != nil {
		fmt.Println(err)
		return []string{}
	}
	var symsSlice []string
	for _, v := range syms {
		symsSlice = append(symsSlice, v.Name)
	}
	return symsSlice
}

func GetMachOImportedSymbolsSlim(arch *macho.File) []string {
	syms, err := arch.ImportedSymbols()
	if err != nil {
		fmt.Println(err)
		return []string{}
	}
	var symsSlice []string
	for _, v := range syms {
		symsSlice = append(symsSlice, v.Name)
	}
	return symsSlice
}

func GetMachOExportedSymbols(arch macho.FatArch) []string {
	var results []string
	exports, err := arch.DyldExports()
	if err != nil {
		fmt.Println(err)
		return results
	}

	for _, export := range exports {
		results = append(results, export.Name)
	}
	return results
}

func GetMachOExportedSymbolsSlim(arch *macho.File) []string {
	var results []string
	exports, err := arch.DyldExports()
	if err != nil {
		fmt.Println(err)
		return results
	}

	for _, export := range exports {
		results = append(results, export.Name)
	}
	return results
}

func GetMachOLibraries(arch macho.FatArch) []string {

	return arch.ImportedLibraries()
}

func GetMachOLibrariesSlim(arch *macho.File) []string {
	return arch.ImportedLibraries()
}

func IsDylib(arch macho.FatArch) bool {
	if arch.FileHeader.Type.String() == "DYLIB" {
		return true
	}
	return false
}

func IsDylibSlim(arch *macho.File) bool {
	if arch.FileHeader.Type.String() == "DYLIB" {
		return true
	}
	return false
}

func GetInsights(file AnalyzedFile, fileContents []byte) []string {
	var result []string

	// VirusTotal Reputation
	if file.VTTotal == 0 {
		result = append(result, "File not found on VirusTotal")
	} else if file.VTTotal == -1 {
		result = append(result, "Please set VTAPI environment variable.\n\tGo to https://support.virustotal.com/hc/en-us/articles/115002100149-API\n\tfor instructions on how to retrieve your key.")
	} else if file.VTTotal == -2 {
		result = append(result, "VirusTotal API Rate Limit exceeded")
	} else if file.VTTotal == -3 {
		result = append(result, "VirusTotal API: Unknown error.")
	} else {
		vt := fmt.Sprintf("%d/%d vendors on VirusTotal detected the file as malicious.", file.VTPositive, file.VTTotal)
		result = append(result, vt)
	}

	// MIME Type
	if file.MIMEType == "application/x-bzip2" {
		result = append(result, "File is a DMG file, please mount before analyzing.")
	} else if file.MIMEType != "" {
		result = append(result, "MIME Type: "+file.MIMEType)
	}

	// is it a DYLIB?
	if file.IsDylib {
		result = append(result, "Mach-O Dynamic Library file")
	}

	// Digital Signature
	if len(file.Signatures) > 0 {
		result = append(result, "File is digitally signed by "+file.Signatures[len(file.Signatures)-1])
	} else {
		result = append(result, "The file is not signed.")
	}

	// Return insight if there's a match
	// some day I would love for this to be a YARA plugin instead

	// do all of this work concurrently for speed
	var wg sync.WaitGroup

	// check for UPX packer toolmarks
	wg.Add(1)
	go func() {
		upx := regexp.MustCompile("upxTEXT")
		if upx.Match(fileContents) {
			result = append(result, "The file is UPX packed. Unpack before proceeding.")
		}
		wg.Done()
	}()

	// is it likely an Electron app?
	wg.Add(1)
	go func() {
		electron := regexp.MustCompile("@_ElectronMain")
		if electron.Match(fileContents) {
			result = append(result, "The file an Electron App. Extract and analyze the ASAR file.")
		}
		wg.Done()
	}()

	// is it likely an Electron app?
	wg.Add(1)
	go func() {
		pyInstaller := regexp.MustCompile("Py_SetPythonHome")
		if pyInstaller.Match(fileContents) {
			result = append(result, "The file is packaged by PyInstaller. Extract and analyze embedded Python.")
		}
		wg.Done()
	}()

	// csrutil status - is SIP enabled?
	wg.Add(1)
	go func() {
		csrutil := regexp.MustCompile("(?i)csrutil\\sstatus")
		if csrutil.Match(fileContents) {
			result = append(result, "The file may use 'csrutil' to query System Integrity Protection status.")
		}
		wg.Done()
	}()

	// screencapture
	wg.Add(1)
	go func() {
		screencap := regexp.MustCompile("(?i)screencapture\\s")
		if screencap.Match(fileContents) {
			result = append(result, "The file may use 'screencapture' to capture system screenshots.")
		}
		wg.Done()
	}()

	// xattr.*com.apple.quarantine
	wg.Add(1)
	go func() {
		quarantine := regexp.MustCompile("(?i)xattr\\s.*com.apple.quarantine")
		if quarantine.Match(fileContents) {
			result = append(result, "The file may use 'xattr' to manipulate file quarantine attributes")
		}
		wg.Done()
	}()

	// anti-VM checks
	wg.Add(1)
	go func() {
		antiVM := regexp.MustCompile("(?i)virtualbox|oracle|vmware|parallels")
		if antiVM.Match(fileContents) {
			result = append(result, "The file may strings that may be related to virtual machine detection.\n")
		}
		wg.Done()
	}()

	// Return text of all matches

	// launchctl references
	wg.Add(1)
	go func() {
		launchctl := regexp.MustCompile("(?i)launchctl\\s.{0,35}")
		for k, match := range launchctl.FindAll(fileContents, -1) {
			if k == 0 {
				result = append(result, "The file may be using launchctl to persist.")
			}
			result = append(result, "\t"+string(match))
		}
		wg.Done()
	}()

	// curl references for ingress tool transfer, bypassing quarantine attribute
	wg.Add(1)
	go func() {
		curl := regexp.MustCompile("(?i)curl\\s.{0,35}")
		for k, match := range curl.FindAll(fileContents, -1) {
			if k == 0 {
				result = append(result, "The file may be using curl to retrieve an additional payload.")
			}
			result = append(result, "\t"+string(match))
		}
		wg.Done()
	}()

	// find http(s) urls
	wg.Add(1)
	go func() {
		webUrl := regexp.MustCompile("(?i)https?://[a-zA-Z0-9\\./]{4,99}")
		for k, match := range webUrl.FindAll(fileContents, -1) {
			if k == 0 {
				result = append(result, "The file contains the following URLs:")
			}
			result = append(result, "\t"+string(match))
		}
		wg.Done()
	}()

	// runs native osacript/osacompile commands
	wg.Add(1)
	go func() {
		osascript := regexp.MustCompile("(?i)(osascript|osacompile).{0,35}")
		for k, match := range osascript.FindAll(fileContents, -1) {
			if k == 0 {
				result = append(result, "The file may use osascript for malicious behavior:")
			}
			result = append(result, "\t"+string(match))
		}
		wg.Done()
	}()

	// wait for all concurrent work to complete
	wg.Wait()

	return stringDedup(result)
}

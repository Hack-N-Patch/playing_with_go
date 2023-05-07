package main

import (
	"bytes"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/blacktop/go-macho"
	"io"
	"macOsTriage/internal"
)

func analyze(reader fyne.URIReadCloser) internal.AnalyzedFile {
	var file internal.AnalyzedFile

	fileContents, err := io.ReadAll(reader)
	if err != nil {
		fmt.Println(err)
		return internal.AnalyzedFile{}
	}

	file.Md5, file.Sha1, file.Sha256 = internal.GetHashes(fileContents)
	file.VTPositive, file.VTTotal = internal.CheckVirusTotal(file.Sha256)
	file.Strings = internal.GetAsciiStrings(fileContents)
	// application/x-mach-binary
	// application/x-bzip2 == DMG file
	// .PKG and .APP files are handled by the open dialog box, treating them as folders
	file.MIMEType = internal.DetermineFileType(fileContents)

	// reader.URI().String() appends "file://" to the beginning of the actual path
	// standard binaries on macOS are "fat" and contain executable code for multiple CPU architectures
	// the code in each is identical

	// create the macho file from the slice of bytes already in memory
	machoFile, err := macho.NewFatFile(bytes.NewReader(fileContents))

	if err == macho.ErrNotFat {
		slimMacho, err := macho.NewFile(bytes.NewReader(fileContents))
		if err != nil {
			fmt.Println("machoFile error: ", err)
		}
		file.Imports = internal.GetMachOLibrariesSlim(slimMacho)
		file.Exports = internal.GetMachOExportedSymbolsSlim(slimMacho)
		file.SectionNames = internal.GetSectionNamesSlim(slimMacho)
		file.Symbols = internal.GetMachOImportedSymbolsSlim(slimMacho)
		file.Signatures = internal.GetDigitalSignaturesSlim(slimMacho)
		file.IsDylib = internal.IsDylibSlim(slimMacho)
		file.IsValidMacho = true
		defer slimMacho.Close()
	} else if err != nil {
		fmt.Println("machoFile error: ", err)
		file.IsValidMacho = false
	} else {
		machoContents := machoFile.Arches[0]
		file.Imports = internal.GetMachOLibraries(machoContents)
		file.SectionNames = internal.GetSectionNames(machoContents)
		file.Symbols = internal.GetMachOImportedSymbols(machoContents)
		file.Signatures = internal.GetDigitalSignatures(machoContents)
		file.IsDylib = internal.IsDylib(machoContents)
		file.IsValidMacho = true
		file.Exports = internal.GetMachOExportedSymbols(machoContents)
		defer machoFile.Close()
	}

	file.Insights = internal.GetInsights(file, fileContents)

	return file
}

func main() {

	// create the new app and window
	a := app.New()
	w := a.NewWindow("Mach-O Triage")

	var file internal.AnalyzedFile

	// on application launch, prompt to open file
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		w.SetTitle(w.Title() + " " + reader.URI().String()[7:])
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		if reader == nil {
			return
		}

		file = analyze(reader)
	}, w)

	// Create the scrollable text boxes
	insights := widget.NewLabel("Insights")
	insightsScroll := container.NewScroll(insights)
	insightsScroll.Hide()

	hashes := widget.NewLabel("Hashes")
	hashesScroll := container.NewScroll(hashes)
	hashesScroll.Hide()

	// strings needs to be a list instead of a text box due to the volume of data
	// Fyne doesn't optimize text boxes for the volume of data I'm throwing at it
	var asciiStrings []string
	ascii := widget.NewList(
		func() int {
			asciiStrings = file.Strings
			return len(asciiStrings)
		},
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(asciiStrings[i])
		},
	)
	ascii.Hide()

	digsig := widget.NewLabel("Digital Signature")
	digsigScroll := container.NewScroll(digsig)
	digsigScroll.Hide()

	machO := widget.NewLabel("Macho-O Data")
	machOScroll := container.NewScroll(machO)
	machOScroll.Hide()

	imports := widget.NewLabel("Libraries")
	importsScroll := container.NewScroll(imports)
	importsScroll.Hide()

	exports := widget.NewLabel("Exports")
	exportsScroll := container.NewScroll(exports)
	exportsScroll.Hide()

	var symbolStrings []string
	symbols := widget.NewList(
		func() int {
			symbolStrings = file.Symbols
			return len(symbolStrings)
		},
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(symbolStrings[i])
		},
	)
	symbols.Hide()

	// Create the selector buttons
	insightsButton := widget.NewButton("Insights", func() {
		// Insights will contain the "most interesting" bits of the sample
		var content string
		for _, insight := range file.Insights {
			content += insight + "\n"
		}

		insights.SetText(content)
		// hide/show the appropriate windows
		insightsScroll.Show()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Hide()
		symbols.Hide()
	})

	hashesButton := widget.NewButton("File Hashes", func() {
		content := fmt.Sprintf("SHA256: \t%s\nSHA1: \t\t%s\nMD5: \t\t%s\n", file.Sha256, file.Sha1, file.Md5)
		hashes.SetText(content)
		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Show()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Hide()
		symbols.Hide()
	})

	asciiButton := widget.NewButton("ASCII Strings", func() {
		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Show()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Hide()
		ascii.Refresh()
		symbols.Hide()
	})

	digsigButton := widget.NewButton("Digital Signature", func() {
		var content string
		for _, section := range file.Signatures {
			content += section + "\n"
		}
		digsig.SetText(content)

		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Show()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Hide()
		symbols.Hide()
	})

	machOButton := widget.NewButton("Section Names", func() {
		var content string
		for _, section := range file.SectionNames {
			content += section + "\n"
		}
		machO.SetText(content)

		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Show()
		importsScroll.Hide()
		exportsScroll.Hide()
		symbols.Hide()
	})

	importsButton := widget.NewButton("Libraries", func() {
		var content string
		for _, lib := range file.Imports {
			content += lib + "\n"
		}
		imports.SetText(content)

		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Show()
		exportsScroll.Hide()
		symbols.Hide()
	})

	exportsButton := widget.NewButton("Exports", func() {
		var content string
		for _, export := range file.Exports {
			content += export + "\n"
		}
		exports.SetText(content)

		// hide/show the appropriate windows
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Show()
		symbols.Hide()
	})

	symbolsButton := widget.NewButton("Symbols", func() {
		insightsScroll.Hide()
		hashesScroll.Hide()
		ascii.Hide()
		digsigScroll.Hide()
		machOScroll.Hide()
		importsScroll.Hide()
		exportsScroll.Hide()
		symbols.Show()
		symbols.Refresh()
	})

	// Assemble the left and right sides
	// the order parameters of the left container controls the display
	var left *fyne.Container
	var right *fyne.Container

	left = container.NewVBox(insightsButton, hashesButton, digsigButton, importsButton, exportsButton, machOButton, symbolsButton, asciiButton)
	right = container.NewMax(insightsScroll, hashesScroll, digsigScroll, importsScroll, exportsScroll, machOScroll, symbols, ascii)
	ascii.Refresh()
	symbols.Refresh()
	insights.Refresh()

	// Create the H-split
	split := container.NewHSplit(left, right)
	split.Offset = 0.2

	// Set the content of the window and display it
	w.SetContent(split)
	w.Resize(fyne.NewSize(1000, 600))
	w.ShowAndRun()
}

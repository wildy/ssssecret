package main

import (
	"log"

	fyneapp "fyne.io/fyne/v2/app"

	"github.com/wildy/ssssecret/internal/appui"
)

const appId string = "ssssecret"

func main() {
	a := fyneapp.NewWithID(appId)
	w := a.NewWindow("Paper Secret Share (Shamir + AES-256 + QR + PDF)")
	w.Resize(appui.DefaultWindowSize())

	ui, err := appui.Build(w)
	if err != nil {
		log.Fatal(err)
	}
	w.SetContent(ui)
	w.ShowAndRun()
}

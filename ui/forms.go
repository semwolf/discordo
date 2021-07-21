package ui

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func NewLoginForm(via string, onLoginFormLoginButtonSelected func(), onLoginFormQuitButtonSelected func()) (loginForm *tview.Form) {
	loginForm = tview.NewForm().
		AddButton("Login", onLoginFormLoginButtonSelected).
		AddButton("Quit", onLoginFormQuitButtonSelected)
	loginForm.
		SetButtonBackgroundColor(tcell.GetColor("#5865F2")).
		SetBorder(true).
		SetBorderPadding(0, 0, 1, 1)

	if via == "token" {
		loginForm.AddPasswordField("Token", "", 0, 0, nil)
	} else if via == "emailpassword" {
		loginForm.
			AddInputField("Email", "", 0, nil, nil).
			AddPasswordField("Password", "", 0, 0, nil)
	}

	return loginForm
}

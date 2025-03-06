package config

import (
	_ "embed"
	"html/template"
)

type onBoardingTmplData struct {
	NavSetupLink  string
	NavStatusLink string
	CertPath      string
	CertLink      string
	PACLink       string
	Version       string
	Backend       string
}

//go:embed pages/index.html
var statusPage string

//go:embed pages/setup.html
var setupPage string

var setupTmpl *template.Template
var statusTmpl *template.Template

func init() {
	var err error
	if setupTmpl, err = template.New("setup").Parse(setupPage); err != nil {
		panic(err)
	}
	if statusTmpl, err = template.New("status").Parse(statusPage); err != nil {
		panic(err)
	}
}

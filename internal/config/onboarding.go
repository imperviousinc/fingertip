package config

import "html/template"

type onBoardingTmplData struct {
	CertPath string
	CertLink string
	PACLink  string
	Version  string
}

var onBoardingTmplContent = `
<!DOCTYPE html>
<html>
    <head>
        <style>
            body {
                font-size: 16px;
                font-family: -apple-system, BlinkMacSystemFont, Segoe UI, PingFang SC, Hiragino Sans GB, Microsoft YaHei, Helvetica Neue, Helvetica, Arial, sans-serif, Apple Color Emoji, Segoe UI Emoji, Segoe UI Symbol;
            }
            h1 {
                color: #444444;
            }
            .c {
                max-width: 600px;
                margin: 0 auto;
                margin-top: 6em;
            }
            .step {
                background: #0e0e0e;
                color: #fff;
                width: 1.5em;
                height: 1.5em;
                display: inline-block;
                text-align: center;
                line-height: 1.5em;
                border-radius: 1.5em;
                padding: 0.2em;
                margin-right: 0.5em;
                font-size: 0.8em;
            }
            .btn {
                background-color: #464646;
                color: #fff;
                border: none;
                border-radius: 4px;
                padding: 0.8em 1.2em;
                font-size: 0.8em;
                margin-left: 0.1em;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="c">
            <h1>Fingertip Setup</h1>
            <h3 style="margin-top: 2em;"><span class="step">1</span> Install Certificate</h3>
            <p>Your private CA is stored at <code>{{.CertPath}}</code>.</p>
            <p>
                It cannot be used to issue certificates for legacy domains (.com, .net ... etc) since it uses the name constraints extension to exclude legacy TLDs from DANE support. Add this CA to your browser/TLS client trust store to
                allow Fingertip to issue certificates for decentralized names.
            </p>

            <div style="margin: 2em 0;">
                <a href="{{.CertLink}}" class="btn">Download Certificate</a>
            </div>

            <h3 style="margin-top: 4em;"><span class="step">2</span> Configure proxy</h3>
            <p>Choose Automatic Proxy configuration in your browser/TLS client proxy settings and add this url:</p>
            <div style="background: #f2f2f2; padding: 1em 2em; font-weight: bold; color: #444;">{{.PACLink}}</div>

            <footer style="margin-top: 2em; border-top: 1px solid #e5e5e5;">
                <small>Fingertip v{{.Version}}</small>
            </footer>
        </div>
    </body>
</html>
`

var onBoardingTmpl *template.Template

func init() {
	var err error
	onBoardingTmpl, err = template.New("index").Parse(onBoardingTmplContent)
	if err != nil {
		panic(err)
	}
}

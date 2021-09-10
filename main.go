package main

import (
	"errors"
	"fingertip/internal/config"
	"fingertip/internal/config/auto"
	"fingertip/internal/resolvers"
	"fingertip/internal/resolvers/proc"
	"fingertip/internal/ui"
	"fmt"
	"github.com/buffrr/letsdane"
	"github.com/buffrr/letsdane/resolver"
	"github.com/emersion/go-autostart"
	"github.com/pkg/browser"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const Version = "0.0.2"

type App struct {
	proc             *proc.HNSProc
	server           *http.Server
	config           *config.App
	usrConfig        *config.User
	proxyURL         string
	autostart        *autostart.App
	autostartEnabled bool
}

var (
	appPath          string
	fileLogger       *log.Logger
	fileLoggerHandle *os.File
)

func setupApp() *App {
	c, err := config.NewConfig()
	if err != nil {
		log.Fatal(err)
	}

	c.Version = Version

	c.DNSProcPath, err = getProcPath()
	if err != nil {
		log.Fatal(err)
	}
	c.DNSProcPath = path.Join(c.DNSProcPath, "hnsd")
	s, err := NewApp(c)
	if err != nil {
		log.Fatal(err)
	}

	return s
}

func onBoardingSeen(name string) bool {
	if _, err := os.Stat(name); err == nil {
		return true
	}
	return false
}

func autoConfigure(app *App, checked, onBoarded bool) bool {
	if !auto.Supported() {
		return false
	}

	autoURL := app.proxyURL + "/proxy.pac"

	if checked {
		confirm := ui.ShowYesNoDlg("Remove Fingertip configuration settings?")
		var err error
		if confirm {
			_ = auto.UninstallAutoProxy()
			err = auto.UninstallCert(app.config.CertPath)
		}

		return !confirm || err != nil
	}

	confirm := ui.ShowYesNoDlg("Automatically configure Fingertip? This allows Fingertip to work with Chrome, Safari and other apps that use the OS trust store and proxy settings.")
	if !confirm {
		// if this is the first time show
		// manual setup instructions instead
		if !onBoarded {
			ui.OnOpenSetup()
		}
		return false
	}

	status, err := auto.GetProxyStatus(autoURL)
	if err != nil {
		ui.ShowErrorDlg(err.Error())
		return false
	}

	// if there are existing proxy settings
	// its better to avoid messing with them
	if status == auto.ProxyStatusConflict {
		ui.ShowErrorDlg("Auto configuration failed your OS has existing proxy settings")
		return false
	}

	if status != auto.ProxyStatusInstalled {
		if err := auto.InstallAutoProxy(autoURL); err != nil {
			ui.ShowErrorDlg(err.Error())
			return false
		}
	}

	if err := auto.InstallCert(app.config.CertPath); err != nil {
		ui.ShowErrorDlg(err.Error())
		return false
	}

	// Enable open at login
	if !ui.Data.OpenAtLogin() {
		enable := ui.OnAutostart(false)
		ui.Data.SetOpenAtLogin(enable)
	}

	return true
}

func main() {
	var err error
	app := setupApp()
	if fileLoggerHandle, err = os.OpenFile(path.Join(app.config.Path, "fingertip.logs"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		log.Fatal(err)
	}
	defer fileLoggerHandle.Close()

	fileLogger = log.New(fileLoggerHandle, "", log.LstdFlags|log.Lshortfile)

	appPath, err = os.Executable()
	if err != nil {
		log.Fatalf("error reading app path: %v", err)
	}

	app.autostart.Exec = []string{appPath}
	if app.autostart.IsEnabled() {
		app.autostartEnabled = true
	}

	hnsErrCh := make(chan error)
	serverErrCh := make(chan error)
	onBoardingFilename := path.Join(app.config.Path, "init")
	onBoarded := onBoardingSeen(onBoardingFilename)

	start := func() {
		app.proc.Start(hnsErrCh)
		ui.Data.SetOptionsEnabled(true)
		ui.Data.SetStarted(true)

		go func() {
			serverErrCh <- app.listen()
		}()

		go func() {
			if onBoarded {
				return
			}

			f, err := os.OpenFile(onBoardingFilename, os.O_RDONLY|os.O_CREATE, 0644)
			if err == nil {
				f.Close()
			}

			ui.Data.SetAutoConfig(autoConfigure(app, false, false))
			onBoarded = true
		}()
	}

	ui.OnStart = start
	ui.OnConfigureOS = func(checked bool) bool {
		return autoConfigure(app, checked, onBoarded)
	}

	ui.OnOpenSetup = func() {
		browser.OpenURL(app.proxyURL)
	}

	ui.OnAutostart = func(checked bool) bool {
		if checked {
			err := app.autostart.Disable()
			if err != nil {
				ui.ShowErrorDlg(fmt.Sprintf("error disabling launch at login: %v", err))
				return checked
			}

			return false
		}

		appPathShown := strings.TrimSuffix(appPath, "/Contents/MacOS/fingertip")
		confirm := true
		// warn if the app doesn't seem to be in a standard path
		if !strings.Contains(appPath, "Program Files") && // windows
			!strings.Contains(appPath, "AppData") && // windows
			!strings.Contains(appPath, "Applications") { // macos

			msg := fmt.Sprintf("Will you keep the app in this path `%s`? \n"+
				"If not move the app to the desired location before "+
				"enabling open at login.", appPathShown)
			confirm = ui.ShowYesNoDlg(msg)
		}

		if !confirm {
			return false
		}

		err = app.autostart.Enable()
		if err != nil {
			ui.ShowErrorDlg(fmt.Sprintf("error enabling open at login: %v", err))
			return false
		}

		return true
	}

	ticker := time.NewTicker(100 * time.Millisecond)

	go func() {
		for {
			select {
			case err := <-serverErrCh:
				if errors.Is(err, http.ErrServerClosed) {
					continue
				}

				ui.ShowErrorDlg(err.Error())
				log.Printf("[ERR] app: proxy server failed: %v", err)

				app.stop()
				ui.Data.SetStarted(false)
			case err := <-hnsErrCh:
				if !app.proc.Started() {
					continue
				}

				// hns process crashed attempt to restart
				// TODO: check if port is already in use

				attempts := app.proc.Retries()
				if attempts > 9 {
					err := fmt.Errorf("[ERR] app: fatal error hnsd process keeps crashing err: %v", err)
					ui.ShowErrorDlg(err.Error())
					app.stop()
					log.Fatal(err)
				}

				// log to a file could be useful for debugging
				line := fmt.Sprintf("[ERR] app: hnsd process crashed restart attempt #%d err: %v", attempts, err)
				log.Printf(line)
				fileLogger.Printf(line)

				// increment retries and restart process
				app.proc.IncrementRetries()
				app.proc.Stop()
				app.proc.Start(hnsErrCh)

			case <-ticker.C:
				if !app.proc.Started() {
					ui.Data.SetBlockHeight("--")
					continue
				}
				ui.Data.SetBlockHeight(fmt.Sprintf("#%d", app.proc.GetHeight()))
			}

		}
	}()

	ui.OnStop = func() {
		app.stop()
		ui.Data.SetOptionsEnabled(false)
		ui.Data.SetStarted(false)
	}

	ui.OnReady = func() {
		ui.Data.SetAutoConfigEnabled(auto.Supported())
		ui.Data.SetOptionsEnabled(false)

		if !onBoarded {
			return
		}

		// update initial state
		ui.Data.SetOpenAtLogin(app.autostartEnabled || ui.Data.OpenAtLogin())

		// TODO: store whether the user has explicitly
		// enabled auto config instead of checking if cert
		// is widely trusted
		autoConfig := auto.Supported() &&
			auto.VerifyCert(app.config.CertPath) == nil

		ui.Data.SetAutoConfig(autoConfig)

		// start fingertip
		start()
	}

	ui.OnExit = func() {
		if fileLoggerHandle != nil {
			fileLoggerHandle.Close()
		}
		app.stop()
	}

	ui.Loop()
}

func NewApp(appConfig *config.App) (*App, error) {
	var err error
	var hnsProc *proc.HNSProc
	app := &App{
		autostart: &autostart.App{
			Name:        config.AppId,
			DisplayName: config.AppName,
			Icon:        "",
		},
	}

	app.config = appConfig
	usrConfig, err := config.ReadUserConfig(appConfig.Path)
	if err != nil && !errors.Is(err, config.ErrUserConfigNotFound) {
		return nil, err
	}

	app.proxyURL = config.GetProxyURL(usrConfig.ProxyAddr)
	app.usrConfig = &usrConfig

	if hnsProc, err = proc.NewHNSProc(appConfig.DNSProcPath, usrConfig.RootAddr, usrConfig.RecursiveAddr); err != nil {
		return nil, err
	}

	app.proc = hnsProc

	app.server, err = app.newProxyServer()
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (a *App) NewResolver() (resolver.Resolver, error) {
	rs, err := resolver.NewStub(a.usrConfig.RecursiveAddr)
	if err != nil {
		return nil, err
	}

	hip5 := resolvers.NewHIP5Resolver(rs, a.usrConfig.RootAddr, a.proc.Synced)
	ethExt, err := resolvers.NewEthereum(a.usrConfig.EthereumEndpoint)
	if err != nil {
		return nil, err
	}

	// Register HIP-5 handlers
	hip5.RegisterHandler("_eth", ethExt.Handler)

	return hip5, nil
}

func (a *App) listen() error {
	return a.server.ListenAndServe()
}

func (a *App) stop() {
	a.proc.Stop()
	a.server.Close()

	// on stop create a new server
	// to reset any state like old cache ... etc.
	var err error
	if a.server, err = a.newProxyServer(); err != nil {
		log.Fatalf("app: error creating a new proxy server: %v", err)
	}
}

func (a *App) newProxyServer() (*http.Server, error) {
	var err error

	// add a new resolver to the proxy config
	if a.config.Proxy.Resolver, err = a.NewResolver(); err != nil {
		return nil, err
	}

	// initialize a new handler
	h, err := a.config.Proxy.NewHandler()
	if err != nil {
		return nil, err
	}

	// copy proxy address from user specified config
	a.config.ProxyAddr = a.usrConfig.ProxyAddr
	server := &http.Server{Addr: a.config.ProxyAddr, Handler: h}
	return server, nil
}

func getProcPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}

	exePath := filepath.Dir(exe)
	return exePath, nil
}

func init() {
	// letsdane shows the version name
	// in the footer on errors
	// 0.6 is the version used in go.mod
	letsdane.Version = fmt.Sprintf("0.6 - fingertip (v%s)", Version)
}

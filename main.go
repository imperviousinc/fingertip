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
	"time"
)

const Version = "0.0.3"

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
	app, err := NewApp(c)
	if err != nil {
		log.Fatal(err)
	}

	return app
}

func onBoardingSeen(name string) bool {
	if _, err := os.Stat(name); err == nil {
		return true
	}
	return false
}

func autoConfigure(app *App, checked, onBoarded bool) bool {
	// TODO: delete once linux is supported
	if !auto.Supported() {
		if !onBoarded {
			browser.OpenURL(app.proxyURL + "/setup")
		}
		return false
	}

	autoURL := app.proxyURL + "/proxy.pac"

	if checked {
		confirm := ui.ShowYesNoDlg("Remove Fingertip configuration settings?")
		if confirm {
			auto.UninstallAutoProxy(autoURL)
			auto.UndoFirefoxConfiguration()
			_ = auto.UninstallCert(app.config.CertPath)
			return false
		}

		return checked
	}

	confirm := ui.ShowYesNoDlg("Would you like to automatically configure Fingertip?")
	if !confirm {
		// if this is the first time show
		// manual setup instructions instead
		if !onBoarded {
			browser.OpenURL(app.proxyURL + "/setup")
		}
		return false
	}

	if err := auto.InstallAutoProxy(autoURL); err != nil {
		ui.ShowErrorDlg(err.Error())
		return false
	}

	_ = auto.ConfigureFirefox()

	if err := auto.InstallCert(app.config.CertPath); err != nil {
		// revert proxy settings
		auto.UninstallAutoProxy(autoURL)
		auto.UndoFirefoxConfiguration()

		ui.ShowErrorDlg(err.Error())
		return false
	}

	// Enable open at login
	if !ui.Data.OpenAtLogin() {
		enable := ui.OnAutostart(false)
		ui.Data.SetOpenAtLogin(enable)
	}

	if time.Since(app.config.Debug.GetLastPing()) > 5*time.Second {
		browser.OpenURL(app.proxyURL)
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

			autoConf := autoConfigure(app, false, false)
			ui.Data.SetAutoConfig(autoConf)

			app.config.Store.AutoConfig = autoConf
			go app.config.Store.Save()

			onBoarded = true
		}()
	}

	ui.OnStart = start
	ui.OnConfigureOS = func(checked bool) bool {
		res := autoConfigure(app, checked, onBoarded)
		app.config.Store.AutoConfig = res
		go app.config.Store.Save()

		return res
	}

	ui.OnOpenHelp = func() {
		browser.OpenURL(app.proxyURL)
	}

	ui.OnAutostart = func(checked bool) bool {
		if checked {
			if err := app.autostart.Disable(); err != nil {
				ui.ShowErrorDlg(fmt.Sprintf("error disabling open at login: %v", err))
				return checked
			}
			return false
		}

		if err = app.autostart.Enable(); err != nil {
			ui.ShowErrorDlg(fmt.Sprintf("error enabling open at login: %v", err))
			return false
		}

		return true
	}

	ticker := time.NewTicker(150 * time.Millisecond)

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
					app.config.Debug.SetBlockHeight(0)
					continue
				}

				height := app.proc.GetHeight()
				ui.Data.SetBlockHeight(fmt.Sprintf("#%d", height))
				app.config.Debug.SetBlockHeight(height)
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
		app.config.Debug.SetCheckCert(func() bool {
			return auto.VerifyCert(app.config.CertPath) == nil
		})
		// update initial state
		ui.Data.SetOpenAtLogin(app.autostartEnabled || ui.Data.OpenAtLogin())

		autoConfig := auto.Supported() &&
			app.config.Store.AutoConfig

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
	hnsProc.SetUserAgent("fingertip:" + Version)

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
	hip5.SetQueryMiddleware(a.config.Debug.GetDNSProbeMiddleware())
	a.config.Debug.SetCheckSynced(a.proc.Synced)

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
	// 0.6.1 is the version used in go.mod
	letsdane.Version = fmt.Sprintf("0.6.1 - fingertip (v%s)", Version)
}

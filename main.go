package main

import (
	"errors"
	"fingertip/internal/config"
	"fingertip/internal/resolvers"
	"fingertip/internal/resolvers/proc"
	"fingertip/internal/ui"
	"fmt"
	"github.com/buffrr/letsdane"
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

type App struct {
	proc             *proc.HNSProc
	hip5             *resolvers.HIP5Resolver
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

			browser.OpenURL(app.proxyURL)
		}()
	}

	ui.OnStart(start)

	ui.OnAutostart(func(checked bool) bool {
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
	})

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
				ui.Data.UpdateUI()
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

	ui.OnStop(func() {
		app.stop()
	})

	ui.OnReady(func() {
		if !onBoarded {
			return
		}

		start()
		ui.Data.SetStarted(true)
		ui.Data.SetOpenAtLogin(app.autostartEnabled)
		ui.Data.UpdateUI()
	})

	ui.OnExit(func() {
		if fileLoggerHandle != nil {
			fileLoggerHandle.Close()
		}
		app.stop()
	})

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

	app.hip5 = resolvers.NewHIP5Resolver(app.proc.Client, usrConfig.RootAddr, hnsProc.Synced)
	eth, err := resolvers.NewEthereum(usrConfig.EthereumEndpoint)
	if err != nil {
		return nil, err
	}

	app.hip5.RegisterHandler("_eth", eth.Handler)
	appConfig.Proxy.Resolver = app.hip5

	app.server, err = newProxy(appConfig, usrConfig.ProxyAddr)
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (s *App) listen() error {
	return s.server.ListenAndServe()
}

func (s *App) stop() {
	s.proc.Stop()
	s.server.Close()
	s.server = &http.Server{
		Addr:    s.server.Addr,
		Handler: s.server.Handler,
	}
}

func newProxy(c *config.App, proxyAddr string) (*http.Server, error) {
	h, err := c.Proxy.NewHandler()
	if err != nil {
		return nil, err
	}
	c.ProxyAddr = proxyAddr
	server := &http.Server{Addr: c.ProxyAddr, Handler: h}
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
	// set version used in go.mod
	letsdane.Version = "0.6-fingertip"
}

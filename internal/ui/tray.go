package ui

import (
	"fingertip/internal/config"
	"fingertip/internal/ui/icon"
	"fmt"
	"github.com/getlantern/systray"
	"sync"
)

var (
	OnExit        func()
	OnStart       func()
	OnAutostart   func(checked bool) bool
	OnConfigureOS func(checked bool) bool
	OnOpenSetup   func()
	OnStop        func()
	OnReady       func()
	Data          State
)

func Loop() {
	systray.Run(Data.initMenu, OnExit)
}

type State struct {
	started     bool
	runToggle   *systray.MenuItem
	openAtLogin *systray.MenuItem
	blockHeight *systray.MenuItem
	options     *systray.MenuItem
	quit        *systray.MenuItem

	autoConfig *systray.MenuItem
	openSetup  *systray.MenuItem

	sync.RWMutex
}

// space padding for width
var startTitle = fmt.Sprintf("%-35s", "Start")
var stopTitle = fmt.Sprintf("%-35s", "Stop")

func (s *State) SetBlockHeight(h string) {
	s.Lock()
	defer s.Unlock()
	if s.blockHeight == nil {
		return
	}
	s.blockHeight.SetTitle("Block height " + h)
}

func (s *State) Started() bool {
	s.RLock()
	defer s.RUnlock()

	return s.started
}

func (s *State) toggleStarted() bool {
	if s.Started() {
		s.SetStarted(false)
		return false
	}

	return true
}

func (s *State) SetStarted(started bool) {
	s.Lock()
	defer s.Unlock()

	s.started = started

	if s.started {
		s.runToggle.SetTitle(stopTitle)
	} else {
		s.runToggle.SetTitle(startTitle)
		s.blockHeight.SetTitle("Block height --")
	}
}

func (s *State) SetOpenAtLogin(checked bool) {
	if checked {
		s.openAtLogin.Check()
		return
	}
	s.openAtLogin.Uncheck()
}

func (s *State) OpenAtLogin() bool {
	return s.openAtLogin.Checked()
}

func (s *State) SetAutoConfig(checked bool) {
	if checked {
		s.autoConfig.Check()
		return
	}

	s.autoConfig.Uncheck()
}

func (s *State) SetAutoConfigEnabled(enabled bool) {
	if enabled {
		s.autoConfig.Enable()
		return
	}

	s.autoConfig.Disable()
}

func (s *State) SetOptionsEnabled(enabled bool) {
	if enabled {
		s.options.Enable()
		return
	}
	s.options.Disable()
}

func (s *State) initMenu() {
	systray.SetTemplateIcon(icon.Toolbar, icon.Toolbar)
	systray.SetTooltip(config.AppName)

	s.runToggle = systray.AddMenuItem(startTitle, "")
	s.openAtLogin = systray.AddMenuItemCheckbox("Open at login", "Open at login", false)

	systray.AddSeparator()
	s.blockHeight = systray.AddMenuItem("Block height --", "Block height")
	s.blockHeight.Disable()

	systray.AddSeparator()
	s.options = systray.AddMenuItem("Options", "")

	s.autoConfig = s.options.AddSubMenuItemCheckbox("Auto configure", "", false)
	s.openSetup = s.options.AddSubMenuItem("Help", "")

	s.quit = systray.AddMenuItem("Quit", "")

	OnReady()

	go func() {
		for {
			select {
			case <-s.runToggle.ClickedCh:
				if s.toggleStarted() {
					OnStart()
					continue
				}

				OnStop()
			case <-s.openAtLogin.ClickedCh:
				s.SetOpenAtLogin(OnAutostart(s.openAtLogin.Checked()))
			case <-s.autoConfig.ClickedCh:
				s.SetAutoConfig(OnConfigureOS(s.autoConfig.Checked()))
			case <-s.openSetup.ClickedCh:
				OnOpenSetup()
				continue
			case <-s.quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

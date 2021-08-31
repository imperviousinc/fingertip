package ui

import (
	"fingertip/internal/config"
	"fingertip/internal/ui/icon"
	"fmt"
	"github.com/getlantern/systray"
	"sync"
)

var (
	onExit      func()
	onStart     func()
	onAutostart func(checked bool) bool
	onStop      func()
	onReady     func()
)

func OnExit(handle func()) {
	onExit = handle
}

func OnStart(handleOnStart func()) {
	onStart = handleOnStart
}

func OnStop(handle func()) {
	onStop = handle
}

func OnReady(handle func()) {
	onReady = handle
}

func OnAutostart(handle func(checked bool) bool) {
	onAutostart = handle
}

func Loop() {
	systray.Run(Data.onReady, onExit)
}

type State struct {
	started     bool
	autostart   bool
	runToggle   *systray.MenuItem
	openAtLogin *systray.MenuItem
	blockHeight *systray.MenuItem
	quit        *systray.MenuItem

	sync.RWMutex
}

var (
	Data State
)

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

func (s *State) UpdateUI() {
	s.Lock()
	defer s.Unlock()

	if Data.started {
		s.runToggle.SetTitle(stopTitle)

	} else {
		s.runToggle.SetTitle(startTitle)
		s.blockHeight.SetTitle("Block height --")
	}

	if Data.autostart {
		s.openAtLogin.Check()
	} else {
		s.openAtLogin.Uncheck()
	}
}

func (s *State) toggleStarted() bool {
	s.Lock()
	defer s.Unlock()
	Data.started = !Data.started

	return Data.started
}

func (s *State) SetStarted(started bool) {
	s.Lock()
	defer s.Unlock()

	Data.started = started
}

func (s *State) SetOpenAtLogin(autostart bool) {
	s.Lock()
	defer s.Unlock()

	Data.autostart = autostart
}

func (s *State) onReady() {
	systray.SetTemplateIcon(icon.Toolbar, icon.Toolbar)
	systray.SetTooltip(config.AppName)

	Data.runToggle = systray.AddMenuItem(startTitle, "Start")
	Data.openAtLogin = systray.AddMenuItemCheckbox("Open at login", "Open at login", false)

	systray.AddSeparator()
	Data.blockHeight = systray.AddMenuItem("Block height --", "Block height")
	Data.blockHeight.Disable()

	systray.AddSeparator()
	Data.quit = systray.AddMenuItem("Quit", "Quit")

	onReady()

	go func() {
		for {
			select {
			case <-s.runToggle.ClickedCh:
				if s.toggleStarted() {
					onStart()
					s.UpdateUI()
					continue
				}

				onStop()
				s.UpdateUI()
			case <-s.openAtLogin.ClickedCh:
				if onAutostart(s.openAtLogin.Checked()) {
					s.openAtLogin.Check()
					s.SetOpenAtLogin(true)
					continue
				}

				s.SetOpenAtLogin(false)
				s.openAtLogin.Uncheck()
			case <-s.quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

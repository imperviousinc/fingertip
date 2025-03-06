package proc

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HNSProc struct {
	path             string
	args             []string
	resolverAddr     string
	rootAddr         string
	cmd              *exec.Cmd
	Verbose          bool
	procStarted      bool
	height           uint64
	lastHeightUpdate time.Time
	synced           bool
	retryCount       int
	lastRetry        time.Time
	sync.RWMutex
}

func NewHNSProc(procPath string, rootAddr, recursiveAddr string) (*HNSProc, error) {
	home, _ := os.UserHomeDir() //above already fails if it doesn't exist
	pathToCheckpoint := path.Join(home, ".hnsd")
	var args []string
	_, err := os.Stat(pathToCheckpoint)
	if err != nil {
		args = []string{"--ns-host", rootAddr, "--rs-host", recursiveAddr, "--pool-size", "4"}
	} else {
		args = []string{"--ns-host", rootAddr, "--rs-host", recursiveAddr, "--pool-size", "4", "-x", pathToCheckpoint}
	}

	if !strings.HasSuffix(procPath, processExtension) {
		procPath += processExtension
	}

	p := &HNSProc{
		path:         procPath,
		args:         args,
		resolverAddr: recursiveAddr,
		rootAddr:     rootAddr,
		Verbose:      true,
	}

	return p, nil
}

func (h *HNSProc) SetUserAgent(agent string) {
	extra := []string{"--user-agent", agent}
	h.args = append(h.args, extra...)
}

func (h *HNSProc) goStart(stopErr chan<- error) {
	go func() {
		h.cmd = exec.Command(h.path, h.args...)
		h.cmd.SysProcAttr = processAttributes

		pipe, err := h.cmd.StdoutPipe()
		if err != nil {
			log.Printf("[WARN] hns: couldn't read from process %v", err)
			return
		}
		h.cmd.Stderr = h.cmd.Stdout

		if err := h.cmd.Start(); err != nil {
			stopErr <- err
			return
		}

		h.monitor(pipe, stopErr)
	}()

}

func (h *HNSProc) monitor(pipe io.ReadCloser, stopErr chan<- error) {
	sc := bufio.NewScanner(pipe)
	p := "chain ("
	plen := len(p)
	for sc.Scan() {
		t := sc.Text()
		if h.Verbose {
			log.Printf("[INFO] hns: %s", t)
		}

		if !strings.HasPrefix(t, p) {
			continue
		}

		var block []rune
		for _, r := range t[plen:] {
			if r == ')' {
				break
			}
			block = append(block, r)
		}

		val, err := strconv.ParseUint(string(block), 10, 64)
		if err != nil {
			val = 0
		}

		h.SetHeight(val)
		// if we are getting some updates from hnsd process
		// it started successfully so we may want
		// to reset retry count
		h.maybeResetRetries()
	}

	if h.Verbose {
		log.Printf("[INFO] hns: closing process %v", sc.Err())
	}

	if err := h.cmd.Wait(); err != nil {
		stopErr <- fmt.Errorf("process exited %v", err)
		return
	}

	stopErr <- fmt.Errorf("process exited 0")
}

func (h *HNSProc) killProcess() error {
	if h.cmd == nil || h.cmd.Process == nil {
		return nil
	}

	if err := h.cmd.Process.Kill(); err != nil {
		return err
	}

	return nil
}

func (h *HNSProc) Started() bool {
	h.RLock()
	defer h.RUnlock()

	return h.procStarted
}

func (h *HNSProc) SetStarted(s bool) {
	h.Lock()
	defer h.Unlock()

	h.procStarted = s
}

func (h *HNSProc) Retries() int {
	h.RLock()
	defer h.RUnlock()

	return h.retryCount
}

func (h *HNSProc) maybeResetRetries() {
	h.Lock()
	defer h.Unlock()

	if time.Since(h.lastRetry) > 10*time.Minute {
		h.retryCount = 0
		h.lastRetry = time.Time{}
	}
}

func (h *HNSProc) IncrementRetries() {
	h.Lock()
	defer h.Unlock()

	h.retryCount += 1
	h.lastRetry = time.Now()
}

func (h *HNSProc) SetHeight(height uint64) {
	h.Lock()
	defer h.Unlock()

	if h.height == height {
		return
	}

	h.height = height
	h.lastHeightUpdate = time.Now()
}

func (h *HNSProc) GetHeight() uint64 {
	h.RLock()
	defer h.RUnlock()

	return h.height
}

func (h *HNSProc) Synced() bool {
	h.RLock()
	defer h.RUnlock()

	if h.synced {
		return true
	}

	h.synced = !h.lastHeightUpdate.IsZero() &&
		time.Since(h.lastHeightUpdate) > 20*time.Second

	return h.synced
}

func (h *HNSProc) Start(stopErr chan<- error) {
	if h.Started() {
		return
	}

	h.Lock()
	defer h.Unlock()

	h.goStart(stopErr)
	h.procStarted = true

}

func (h *HNSProc) Stop() {
	h.Lock()
	defer h.Unlock()
	h.killProcess()
	h.procStarted = false
	h.height = 0
	h.lastHeightUpdate = time.Time{}
	h.synced = false
}

package proc

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
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
	progress         float64
	retryCount       int
	lastRetry        time.Time
	hsClient         *dns.Client
	sync.RWMutex
}

func NewHNSProc(procPath string, rootAddr, recursiveAddr string, configPath string) (*HNSProc, error) {
	args := []string{"--ns-host", rootAddr, "--rs-host", recursiveAddr, "--pool-size", "4", "-t", "-x", configPath}

	if !strings.HasSuffix(procPath, processExtension) {
		procPath += processExtension
	}

	hsClient := &dns.Client{
		Timeout: 1 * time.Second,
		SingleInflight: true,
	}

	p := &HNSProc{
		path:         procPath,
		args:         args,
		resolverAddr: recursiveAddr,
		rootAddr:     rootAddr,
		hsClient:     hsClient,
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
	for sc.Scan() {
		t := sc.Text()
		if h.Verbose {
			log.Printf("[INFO] hns: %s", t)
		}

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

func (h *HNSProc) goRefreshStatus() {
	go func() {
		ticker := time.NewTicker(1000 * time.Millisecond)

		for range ticker.C {
			if !h.procStarted {
				ticker.Stop()
				break
			}

			// Create DNS Query
			msg := new(dns.Msg)
			msg.SetQuestion("chain.hnsd.", dns.TypeTXT)
			msg.Question[0].Qclass = dns.ClassHESIOD

			// Send the query to hnsd
			resp, _, err := h.hsClient.Exchange(msg, h.rootAddr)
			if err != nil {
				log.Printf("[WARN] hnsd: error querying hnsd dns api: %v", err)
				continue
			}

			// Read and update chain info
			for _, answer := range resp.Answer {
				if txt, ok := answer.(*dns.TXT); ok {
					switch txt.Hdr.Name {

					// height
					case "height.tip.chain.hnsd.":
						height, err := strconv.ParseUint(txt.Txt[0], 10, 64)
						if err != nil {
							height = 0
						}
						h.SetHeight(height)

					// progress
					case "progress.chain.hnsd.":
						progress, err := strconv.ParseFloat(txt.Txt[0], 64)
						if err != nil {
							progress = 0
						}
						h.SetProgress(progress)
					}
				}
			}
		}
	}()
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

func (h *HNSProc) GetChainInfo() (uint64, float64) {
	h.RLock()
	defer h.RUnlock()

	return h.height, h.progress
}

func (h *HNSProc) SetHeight(height uint64) {
	h.Lock()
	defer h.Unlock()

	h.height = height
}

func (h *HNSProc) SetProgress(progress float64) {
	h.Lock()
	defer h.Unlock()

	h.progress = progress
}

func (h *HNSProc) Synced() bool {
	h.RLock()
	defer h.RUnlock()

	return h.progress >= 0.999
}

func (h *HNSProc) Start(stopErr chan<- error) {
	if h.Started() {
		return
	}

	h.Lock()
	defer h.Unlock()

	h.goStart(stopErr)
	h.goRefreshStatus()
	h.procStarted = true

}

func (h *HNSProc) Stop() {
	h.Lock()
	defer h.Unlock()
	h.killProcess()
	h.procStarted = false
	h.height = 0
	h.progress = 0
}

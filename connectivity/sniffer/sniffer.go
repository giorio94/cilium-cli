// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sniffer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// Mode configures the Sniffer validation mode.
type Mode string

const (
	// ModeAssert: do not expect to observe any packets matching the filter.
	ModeAssert Mode = "assert"
	// ModeSanity: expect to observe packets matching the filter, to be
	// leveraged as a sanity check to verify that the filter is correct.
	ModeSanity Mode = "sanity"
)

type sniffer struct {
	host     *check.Pod
	dumpPath string
	mode     Mode

	stdout safeBuffer
	cancel context.CancelFunc
	exited chan error
}

type debugLogger interface {
	Debugf(string, ...interface{})
}

type Sniffer interface {
	// Validate stops the tcpdump capture previously started by StartLeakSniffer and
	// asserts that no packets (or at least one packet when running in sanityMode)
	// got captured. It additionally dumps the captured packets in case of failure
	// if debug logs are enabled.
	Validate(ctx context.Context, a *check.Action)
}

// Start starts a tcpdump capture on the given host-netns pod, listening
// to the specified interface. The mode configures whether Validate() will
// (not) expect any packet to match the filter.
func Start(ctx context.Context, id string, host *check.Pod,
	iface string, filter string, mode Mode, dbg debugLogger,
) (*sniffer, error) {
	cmdctx, cancel := context.WithCancel(ctx)
	snf := &sniffer{
		host:     host,
		dumpPath: fmt.Sprintf("/tmp/%s.pcap", id),
		mode:     mode,
		cancel:   cancel,
		exited:   make(chan error, 1),
	}

	go func() {
		// Run tcpdump with -w instead of directly printing captured pkts. This
		// is to avoid a race after sending ^C (triggered by cancel()) which
		// might terminate the tcpdump process before it gets a chance to dump
		// its captures.
		args := []string{"-i", iface, "--immediate-mode", "-w", snf.dumpPath}
		if snf.mode == ModeSanity {
			// We limit the number of packets to be captures only when expecting
			// them to be seen (i.e., in sanity mode). Otherwise, better to capture
			// them all to provide more informative debug messages.
			args = append(args, "-c", "1")
		}
		cmd := append([]string{"tcpdump"}, append(args, filter)...)

		dbg.Debugf("Starting sniffer in background on %q (mode=%s): %q", host.String(), mode, strings.Join(cmd, " "))
		err := host.K8sClient.ExecInPodWithWriters(ctx, cmdctx,
			host.Pod.Namespace, host.Pod.Name, "", cmd, &snf.stdout, io.Discard)
		if err != nil && !errors.Is(err, context.Canceled) {
			snf.exited <- err
		}

		close(snf.exited)
	}()

	// Wait until tcpdump is ready to capture pkts
	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	for {
		select {
		case <-wctx.Done():
			return nil, fmt.Errorf("Failed to wait for tcpdump to be ready")
		case err := <-snf.exited:
			return nil, fmt.Errorf("Failed to execute tcpdump: %w", err)
		case <-time.After(100 * time.Millisecond):
			line, err := snf.stdout.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("Failed to read kubectl exec's stdout: %w", err)
			}
			if strings.Contains(line, fmt.Sprintf("listening on %s", iface)) {
				return snf, nil
			}
		}
	}
}

func (snf *sniffer) Validate(ctx context.Context, a *check.Action) {
	// Wait until tcpdump has exited
	snf.cancel()
	if err := <-snf.exited; err != nil {
		a.Fatalf("Failed to execute tcpdump: %w", err)
	}

	// Redirect stderr to /dev/null, as tcpdump logs to stderr, and ExecInPod
	// will return an error if any char is written to stderr. Anyway, the count
	// is written to stdout.
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s --count 2>/dev/null", snf.dumpPath)}
	count, err := snf.host.K8sClient.ExecInPod(ctx, snf.host.Pod.Namespace, snf.host.Pod.Name, "", cmd)
	if err != nil {
		a.Fatalf("Failed to retrieve tcpdump packet count: %s", err)
	}

	if !strings.Contains(count.String(), "packet") {
		a.Fatalf("tcpdump output doesn't look correct: %s", count.String())
	}

	if !strings.HasPrefix(count.String(), "0 packets") && snf.mode == ModeAssert {
		a.Failf("Captured unexpected packets (count=%s)", strings.TrimRight(count.String(), "\n\r"))

		// If debug mode is enabled, dump the captured pkts
		if a.DebugEnabled() {
			cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tcpdump -r %s 2>/dev/null", snf.dumpPath)}
			out, err := snf.host.K8sClient.ExecInPod(ctx, snf.host.Pod.Namespace, snf.host.Pod.Name, "", cmd)
			if err != nil {
				a.Fatalf("Failed to retrieve tcpdump output: %s", err)
			}
			a.Debugf("Captured packets:\n%s", out.String())
		}
	}

	if strings.HasPrefix(count.String(), "0 packets") && snf.mode == ModeSanity {
		a.Failf("Expected to capture packets, but none found. This check might be broken")
	}
}

// bytes.Buffer from the stdlib is non-thread safe, thus our custom
// implementation. Unfortunately, we cannot use io.Pipe, as Write() blocks until
// Read() has read all content, which makes it deadlock-prone when used with
// ExecInPodWithWriters() running in a separate goroutine.
type safeBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *safeBuffer) Read(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Read(p)
}

func (b *safeBuffer) Write(p []byte) (n int, err error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(p)
}

func (b *safeBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

func (b *safeBuffer) ReadString(d byte) (string, error) {
	b.Lock()
	defer b.Unlock()
	return b.b.ReadString(d)
}

//go:build darwin || linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"susu/internal/cryptox"
)

func TestReadTTYPasswordOpen(t *testing.T) {
	t.Run("uses /dev/tty read-write", func(t *testing.T) {
		openTestTTY, transcriptPath := newPasswordTestTTYOpener(t)
		var gotName string
		var gotFlag int
		var gotPerm os.FileMode
		openTTY := func(name string, flag int, perm os.FileMode) (*os.File, error) {
			gotName = name
			gotFlag = flag
			gotPerm = perm
			return openTestTTY(name, flag, perm)
		}

		password, err := readTTYPasswordWith(false, openTTY, func(int) ([]byte, error) {
			return []byte("open test password"), nil
		})
		if err != nil {
			t.Fatalf("readTTYPasswordWith() error = %v", err)
		}
		defer cryptox.ZeroBytes(password)
		if gotName != "/dev/tty" {
			t.Errorf("open name = %q, want /dev/tty", gotName)
		}
		if gotFlag != os.O_RDWR {
			t.Errorf("open flag = %#x, want os.O_RDWR (%#x)", gotFlag, os.O_RDWR)
		}
		if gotPerm != 0 {
			t.Errorf("open perm = %#o, want 0", gotPerm)
		}
		if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: \n" {
			t.Errorf("TTY transcript = %q, want %q", got, "Password: \n")
		}
	})

	t.Run("wraps open error", func(t *testing.T) {
		openErr := errors.New("test open failure")
		readCalled := false
		password, err := readTTYPasswordWith(false, func(name string, flag int, perm os.FileMode) (*os.File, error) {
			if name != "/dev/tty" || flag != os.O_RDWR || perm != 0 {
				t.Errorf("open arguments = (%q, %#x, %#o), want (%q, %#x, 0)", name, flag, perm, "/dev/tty", os.O_RDWR)
			}
			return nil, openErr
		}, func(int) ([]byte, error) {
			readCalled = true
			return nil, nil
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readTTYPasswordWith() password = %q, want nil", password)
		}
		if !errors.Is(err, openErr) {
			t.Fatalf("readTTYPasswordWith() error = %v, want wrapped open error", err)
		}
		if !strings.Contains(err.Error(), "open /dev/tty for password input") {
			t.Errorf("readTTYPasswordWith() error = %q, want /dev/tty context", err)
		}
		if readCalled {
			t.Fatal("terminal reader was called after the open error")
		}
	})
}

func TestReadTTYPasswordUnlockReadsOnce(t *testing.T) {
	openTTY, transcriptPath := newPasswordTestTTYOpener(t)
	passwordBuffer := []byte("unlock password")
	readCalls := 0

	password, err := readTTYPasswordWith(false, openTTY, func(int) ([]byte, error) {
		readCalls++
		return passwordBuffer, nil
	})
	if err != nil {
		t.Fatalf("readTTYPasswordWith() error = %v", err)
	}
	defer cryptox.ZeroBytes(password)
	if readCalls != 1 {
		t.Fatalf("terminal reader calls = %d, want 1", readCalls)
	}
	if !bytes.Equal(password, []byte("unlock password")) {
		t.Errorf("password = %q, want unlock password", password)
	}
	if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: \n" {
		t.Errorf("TTY transcript = %q, want %q", got, "Password: \n")
	}
}

func TestReadTTYPasswordCreate(t *testing.T) {
	t.Run("confirms matching password", func(t *testing.T) {
		openTTY, transcriptPath := newPasswordTestTTYOpener(t)
		passwordBuffer := []byte("create password")
		confirmationBuffer := []byte("create password")
		readCalls := 0

		password, err := readTTYPasswordWith(true, openTTY, func(int) ([]byte, error) {
			readCalls++
			switch readCalls {
			case 1:
				return passwordBuffer, nil
			case 2:
				return confirmationBuffer, nil
			default:
				t.Fatalf("unexpected terminal reader call %d", readCalls)
				return nil, nil
			}
		})
		if err != nil {
			t.Fatalf("readTTYPasswordWith() error = %v", err)
		}
		defer cryptox.ZeroBytes(password)
		if readCalls != 2 {
			t.Fatalf("terminal reader calls = %d, want 2", readCalls)
		}
		if !bytes.Equal(password, []byte("create password")) {
			t.Errorf("password = %q, want create password", password)
		}
		requireZeroed(t, "confirmation", confirmationBuffer)
		if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: \nConfirm password: \n" {
			t.Errorf("TTY transcript = %q, want %q", got, "Password: \nConfirm password: \n")
		}
	})

	t.Run("rejects empty password before confirmation", func(t *testing.T) {
		openTTY, transcriptPath := newPasswordTestTTYOpener(t)
		readCalls := 0
		password, err := readTTYPasswordWith(true, openTTY, func(int) ([]byte, error) {
			readCalls++
			return nil, nil
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readTTYPasswordWith() password = %q, want nil", password)
		}
		if err == nil || err.Error() != "password must not be empty" {
			t.Fatalf("readTTYPasswordWith() error = %v, want empty-password error", err)
		}
		if readCalls != 1 {
			t.Fatalf("terminal reader calls = %d, want 1", readCalls)
		}
		if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: \n" {
			t.Errorf("TTY transcript = %q, want %q", got, "Password: \n")
		}
	})

	t.Run("rejects mismatch and zeroes both buffers", func(t *testing.T) {
		openTTY, _ := newPasswordTestTTYOpener(t)
		passwordBuffer := []byte("first password")
		confirmationBuffer := []byte("different password")
		readCalls := 0
		password, err := readTTYPasswordWith(true, openTTY, func(int) ([]byte, error) {
			readCalls++
			if readCalls == 1 {
				return passwordBuffer, nil
			}
			return confirmationBuffer, nil
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readTTYPasswordWith() password = %q, want nil", password)
		}
		if err == nil || err.Error() != "password confirmation does not match" {
			t.Fatalf("readTTYPasswordWith() error = %v, want confirmation-mismatch error", err)
		}
		if readCalls != 2 {
			t.Fatalf("terminal reader calls = %d, want 2", readCalls)
		}
		requireZeroed(t, "password", passwordBuffer)
		requireZeroed(t, "confirmation", confirmationBuffer)
	})

	t.Run("zeroes partial first read on error", func(t *testing.T) {
		openTTY, _ := newPasswordTestTTYOpener(t)
		readErr := errors.New("test first read failure")
		partialPassword := []byte("partial first password")
		readCalls := 0
		password, err := readTTYPasswordWith(true, openTTY, func(int) ([]byte, error) {
			readCalls++
			return partialPassword, readErr
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readTTYPasswordWith() password = %q, want nil", password)
		}
		if !errors.Is(err, readErr) {
			t.Fatalf("readTTYPasswordWith() error = %v, want wrapped read error", err)
		}
		if readCalls != 1 {
			t.Fatalf("terminal reader calls = %d, want 1", readCalls)
		}
		requireZeroed(t, "partial password", partialPassword)
	})

	t.Run("zeroes password and partial confirmation on read error", func(t *testing.T) {
		openTTY, _ := newPasswordTestTTYOpener(t)
		readErr := errors.New("test confirmation read failure")
		passwordBuffer := []byte("first password")
		partialConfirmation := []byte("partial confirmation")
		readCalls := 0
		password, err := readTTYPasswordWith(true, openTTY, func(int) ([]byte, error) {
			readCalls++
			if readCalls == 1 {
				return passwordBuffer, nil
			}
			return partialConfirmation, readErr
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readTTYPasswordWith() password = %q, want nil", password)
		}
		if !errors.Is(err, readErr) {
			t.Fatalf("readTTYPasswordWith() error = %v, want wrapped confirmation read error", err)
		}
		if readCalls != 2 {
			t.Fatalf("terminal reader calls = %d, want 2", readCalls)
		}
		requireZeroed(t, "password", passwordBuffer)
		requireZeroed(t, "partial confirmation", partialConfirmation)
	})
}

func TestReadOnePasswordErrorsAndZeroization(t *testing.T) {
	t.Run("prompt error stops before read", func(t *testing.T) {
		tty, _ := newPasswordTestTTYFile(t)
		if err := tty.Close(); err != nil {
			t.Fatal(err)
		}
		readCalled := false
		password, err := readOnePasswordWith(tty, "Password: ", func(int) ([]byte, error) {
			readCalled = true
			return []byte("must not be returned"), nil
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readOnePasswordWith() password = %q, want nil", password)
		}
		if err == nil {
			t.Fatal("readOnePasswordWith() succeeded, want prompt error")
		}
		if readCalled {
			t.Fatal("terminal reader was called after the prompt error")
		}
	})

	t.Run("newline error zeroes password", func(t *testing.T) {
		tty, transcriptPath := newPasswordTestTTYFile(t)
		passwordBuffer := []byte("password before newline failure")
		password, err := readOnePasswordWith(tty, "Password: ", func(int) ([]byte, error) {
			if err := tty.Close(); err != nil {
				t.Fatalf("close test TTY before newline: %v", err)
			}
			return passwordBuffer, nil
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readOnePasswordWith() password = %q, want nil", password)
		}
		if err == nil {
			t.Fatal("readOnePasswordWith() succeeded, want newline error")
		}
		requireZeroed(t, "password", passwordBuffer)
		if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: " {
			t.Errorf("TTY transcript = %q, want prompt without newline", got)
		}
	})

	t.Run("read error zeroes partial password and still writes newline", func(t *testing.T) {
		tty, transcriptPath := newPasswordTestTTYFile(t)
		readErr := errors.New("test terminal read failure")
		partialPassword := []byte("partial password bytes")
		password, err := readOnePasswordWith(tty, "Password: ", func(int) ([]byte, error) {
			return partialPassword, readErr
		})
		if password != nil {
			cryptox.ZeroBytes(password)
			t.Fatalf("readOnePasswordWith() password = %q, want nil", password)
		}
		if !errors.Is(err, readErr) {
			t.Fatalf("readOnePasswordWith() error = %v, want wrapped read error", err)
		}
		if !strings.Contains(err.Error(), "read password from TTY") {
			t.Errorf("readOnePasswordWith() error = %q, want TTY read context", err)
		}
		requireZeroed(t, "partial password", partialPassword)
		if got := readPasswordTestTranscript(t, transcriptPath); got != "Password: \n" {
			t.Errorf("TTY transcript = %q, want prompt and newline", got)
		}
	})
}

const (
	readTTYPasswordPTYHelperEnv = "SUSU_CLI_READ_TTY_PASSWORD_PTY_HELPER"
	readTTYPasswordPTYCreateEnv = "SUSU_CLI_READ_TTY_PASSWORD_PTY_CREATE"
)

type readTTYPasswordPTYResult struct {
	Password string `json:"password"`
	Error    string `json:"error"`
}

func TestReadTTYPasswordProductionUsesControllingTTYWithoutEcho(t *testing.T) {
	if os.Getenv(readTTYPasswordPTYHelperEnv) == "1" {
		runReadTTYPasswordPTYHelper()
		return
	}

	tests := []struct {
		name       string
		create     bool
		ttySecret  string
		stdinValue string
	}{
		{
			name:       "unlock",
			ttySecret:  "unlock secret from controlling TTY",
			stdinValue: "different unlock password from stdin",
		},
		{
			name:       "create confirmation",
			create:     true,
			ttySecret:  "create secret from controlling TTY",
			stdinValue: "different create password from stdin",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, transcript, err := runReadTTYPasswordPTY(t, test.create, test.ttySecret, test.stdinValue)
			if err != nil {
				t.Fatal(err)
			}
			if result.Error != "" {
				t.Fatalf("readTTYPassword() error = %q", result.Error)
			}
			if result.Password != test.ttySecret {
				t.Fatalf("readTTYPassword() password = %q, want controlling-TTY password %q; stdin contained %q", result.Password, test.ttySecret, test.stdinValue)
			}
			if !strings.Contains(transcript, "Password: ") {
				t.Fatalf("PTY transcript does not contain password prompt: %q", transcript)
			}
			if test.create {
				if !strings.Contains(transcript, "Confirm password: ") {
					t.Fatalf("PTY transcript does not contain confirmation prompt: %q", transcript)
				}
			} else if strings.Contains(transcript, "Confirm password: ") {
				t.Fatalf("unlock PTY transcript contains an unexpected confirmation prompt: %q", transcript)
			}
			if strings.Contains(transcript, test.ttySecret) {
				t.Fatalf("PTY echoed the entered password: %q", transcript)
			}
			if strings.Contains(transcript, test.stdinValue) {
				t.Fatalf("PTY transcript unexpectedly contains stdin password: %q", transcript)
			}
		})
	}
}

func runReadTTYPasswordPTYHelper() {
	password, err := readTTYPassword(os.Getenv(readTTYPasswordPTYCreateEnv) == "1")
	result := readTTYPasswordPTYResult{}
	if password != nil {
		result.Password = string(password)
		cryptox.ZeroBytes(password)
	}
	if err != nil {
		result.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "encode PTY helper result: %v\n", encodeErr)
		os.Exit(2)
	}
	os.Exit(0)
}

func runReadTTYPasswordPTY(t *testing.T, create bool, ttySecret, stdinValue string) (readTTYPasswordPTYResult, string, error) {
	t.Helper()

	stdinPath := filepath.Join(t.TempDir(), "stdin-password")
	stdinContents := stdinValue + "\n" + stdinValue + "\n"
	if err := os.WriteFile(stdinPath, []byte(stdinContents), 0o600); err != nil {
		return readTTYPasswordPTYResult{}, "", fmt.Errorf("write subprocess stdin: %w", err)
	}
	stdin, err := os.Open(stdinPath)
	if err != nil {
		return readTTYPasswordPTYResult{}, "", fmt.Errorf("open subprocess stdin: %w", err)
	}
	defer stdin.Close()

	ptmx, tty, err := pty.Open()
	if err != nil {
		return readTTYPasswordPTYResult{}, "", fmt.Errorf("open PTY: %w", err)
	}
	defer ptmx.Close()
	defer tty.Close()

	initialState, err := term.GetState(int(tty.Fd()))
	if err != nil {
		return readTTYPasswordPTYResult{}, "", fmt.Errorf("get initial PTY state: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReadTTYPasswordProductionUsesControllingTTYWithoutEcho$")
	createValue := "0"
	if create {
		createValue = "1"
	}
	cmd.Env = append(os.Environ(),
		readTTYPasswordPTYHelperEnv+"=1",
		readTTYPasswordPTYCreateEnv+"="+createValue,
	)
	cmd.Stdin = stdin
	var resultOutput bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &resultOutput
	cmd.Stderr = &stderr
	cmd.ExtraFiles = []*os.File{tty}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    3,
	}

	capture := startPTYTranscriptCapture(ptmx)
	started := false
	waited := false
	defer func() {
		if started && !waited {
			cancel()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	if err := cmd.Start(); err != nil {
		return readTTYPasswordPTYResult{}, "", fmt.Errorf("start PTY helper: %w", err)
	}
	started = true

	if err := capture.waitFor("Password: ", 4*time.Second); err != nil {
		return readTTYPasswordPTYResult{}, capture.snapshot(), err
	}
	if err := waitForTerminalStateChange(tty, initialState, 2*time.Second); err != nil {
		return readTTYPasswordPTYResult{}, capture.snapshot(), fmt.Errorf("wait for no-echo password read: %w", err)
	}
	if err := writePTYLine(ptmx, ttySecret); err != nil {
		return readTTYPasswordPTYResult{}, capture.snapshot(), fmt.Errorf("write password to PTY: %w", err)
	}

	if create {
		if err := capture.waitFor("Confirm password: ", 4*time.Second); err != nil {
			return readTTYPasswordPTYResult{}, capture.snapshot(), err
		}
		if err := waitForTerminalStateChange(tty, initialState, 2*time.Second); err != nil {
			return readTTYPasswordPTYResult{}, capture.snapshot(), fmt.Errorf("wait for no-echo confirmation read: %w", err)
		}
		if err := writePTYLine(ptmx, ttySecret); err != nil {
			return readTTYPasswordPTYResult{}, capture.snapshot(), fmt.Errorf("write confirmation to PTY: %w", err)
		}
	}

	waitErr := cmd.Wait()
	waited = true
	if closeErr := tty.Close(); closeErr != nil {
		return readTTYPasswordPTYResult{}, capture.snapshot(), fmt.Errorf("close parent PTY slave: %w", closeErr)
	}
	transcript, transcriptErr := capture.waitDone(2 * time.Second)
	if transcriptErr != nil && !errors.Is(transcriptErr, io.EOF) && !errors.Is(transcriptErr, syscall.EIO) {
		return readTTYPasswordPTYResult{}, transcript, fmt.Errorf("read PTY transcript: %w", transcriptErr)
	}
	if waitErr != nil {
		if ctx.Err() != nil {
			return readTTYPasswordPTYResult{}, transcript, fmt.Errorf("PTY helper exceeded 15-second process timeout: %w", ctx.Err())
		}
		return readTTYPasswordPTYResult{}, transcript, fmt.Errorf("wait for PTY helper: %w; stdout=%q stderr=%q", waitErr, resultOutput.String(), stderr.String())
	}

	var result readTTYPasswordPTYResult
	if err := json.Unmarshal(resultOutput.Bytes(), &result); err != nil {
		return readTTYPasswordPTYResult{}, transcript, fmt.Errorf("decode PTY helper result %q (stderr %q): %w", resultOutput.String(), stderr.String(), err)
	}
	if stderr.Len() != 0 {
		return readTTYPasswordPTYResult{}, transcript, fmt.Errorf("PTY helper stderr = %q, want empty output", stderr.String())
	}
	return result, transcript, nil
}

func waitForTerminalStateChange(tty *os.File, initial *term.State, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()

	for {
		state, err := term.GetState(int(tty.Fd()))
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(state, initial) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return errors.New("terminal state did not change before timeout")
		}
	}
}

func writePTYLine(ptmx *os.File, value string) error {
	data := []byte(value + "\n")
	for len(data) > 0 {
		n, err := ptmx.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type ptyTranscriptCapture struct {
	mu      sync.Mutex
	output  bytes.Buffer
	readErr error
	notify  chan struct{}
	done    chan struct{}
}

func startPTYTranscriptCapture(ptmx *os.File) *ptyTranscriptCapture {
	capture := &ptyTranscriptCapture{
		notify: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buffer)
			if n > 0 {
				capture.mu.Lock()
				_, _ = capture.output.Write(buffer[:n])
				capture.mu.Unlock()
				select {
				case capture.notify <- struct{}{}:
				default:
				}
			}
			if err != nil {
				capture.mu.Lock()
				capture.readErr = err
				capture.mu.Unlock()
				close(capture.done)
				return
			}
		}
	}()
	return capture
}

func (capture *ptyTranscriptCapture) snapshot() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.output.String()
}

func (capture *ptyTranscriptCapture) waitFor(want string, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		transcript := capture.snapshot()
		if strings.Contains(transcript, want) {
			return nil
		}
		select {
		case <-capture.notify:
		case <-capture.done:
			transcript = capture.snapshot()
			if strings.Contains(transcript, want) {
				return nil
			}
			capture.mu.Lock()
			readErr := capture.readErr
			capture.mu.Unlock()
			return fmt.Errorf("PTY closed before %q appeared (transcript %q): %v", want, transcript, readErr)
		case <-timer.C:
			return fmt.Errorf("timed out after %s waiting for %q in PTY transcript %q", timeout, want, transcript)
		}
	}
}

func (capture *ptyTranscriptCapture) waitDone(timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-capture.done:
		capture.mu.Lock()
		defer capture.mu.Unlock()
		return capture.output.String(), capture.readErr
	case <-timer.C:
		return capture.snapshot(), fmt.Errorf("timed out after %s draining PTY transcript", timeout)
	}
}

func newPasswordTestTTYOpener(t *testing.T) (ttyOpener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tty-transcript")
	return func(string, int, os.FileMode) (*os.File, error) {
		return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	}, path
}

func newPasswordTestTTYFile(t *testing.T) (*os.File, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tty-transcript")
	tty, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tty.Close() })
	return tty, path
}

func readPasswordTestTranscript(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func requireZeroed(t *testing.T, name string, buffer []byte) {
	t.Helper()
	for index, value := range buffer {
		if value != 0 {
			t.Fatalf("%s byte %d = %#x, want zeroed buffer", name, index, value)
		}
	}
}

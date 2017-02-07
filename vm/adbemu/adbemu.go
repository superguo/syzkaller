// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"bufio"

	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/vm"
)

const (
	hostAddr = "10.0.2.10"
)

func init() {
	vm.Register("adbemu", ctor)
}

type instance struct {
	cfg     *vm.Config
	port    int
	rpipe   io.ReadCloser
	wpipe   io.WriteCloser
	qemu    *exec.Cmd
	waiterC chan error
	merger  *vm.OutputMerger

	// Android stuffs
	device  string
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	for i := 0; ; i++ {
		inst, err := ctorImpl(cfg)
		if err == nil {
			return inst, nil
		}
		if i < 1000 && strings.Contains(err.Error(), "could not set up host forwarding rule") {
			continue
		}
		os.RemoveAll(cfg.Workdir)
		return nil, err
	}
}

func ctorImpl(cfg *vm.Config) (vm.Instance, error) {
	inst := &instance{cfg: cfg}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.close(false)
		}
	}()

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	var err error
	inst.rpipe, inst.wpipe, err = vm.LongPipe()
	if err != nil {
		return nil, err
	}

	if err := inst.Boot(); err != nil {
		return nil, err
	}

	closeInst = nil
	return inst, nil
}


func containsAvd(emulatorPath string, avd string) bool {
	cmd := exec.Command(emulatorPath, "-list-avds")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	s := bufio.NewReader(stdout)
	for {
		line, err := s.ReadString('\n')
	        if err != nil {
			break
	        }
		line = strings.TrimRight(line, "\r\n")
		if strings.Compare(line, avd) == 0 {
			return true
		}
	}
	return false
}

func validateConfig(cfg *vm.Config) error {
	sdkPath := os.Getenv("ANDROID_SDK")
	if cfg.Bin == "" {
		if sdkPath == "" {
			return fmt.Errorf("ANDROID_SDK must be set")
		}
		cfg.Bin = sdkPath + "/tools/emulator"
	}
	if cfg.Image == "9p" {
		return fmt.Errorf("9p image is not unsupported")
	}
	if cfg.Kernel != "" {
		if _, err := os.Stat(cfg.Kernel); err != nil {
			return fmt.Errorf("kernel image file '%v' does not exist: %v", cfg.Image, err)
		}
	}
	if !containsAvd(cfg.Bin, cfg.Avd) {
		return fmt.Errorf("avd '%v' doest not exist", cfg.Avd)
	}
	return nil
}


func (inst *instance) Close() {
	inst.close(true)
}

func (inst *instance) close(removeWorkDir bool) {
	if inst.qemu != nil {
		inst.qemu.Process.Kill()
		err := <-inst.waiterC
		inst.waiterC <- err // repost it for waiting goroutines
	}
	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}
	os.Remove(filepath.Join(inst.cfg.Workdir, "key"))
	if removeWorkDir {
		os.RemoveAll(inst.cfg.Workdir)
	}
}

func (inst *instance) Boot() error {
	for {
		// Find an unused TCP port.
		inst.port = rand.Intn(64<<10-1<<10) + 1<<10
		ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%v", inst.port))
		if err == nil {
			ln.Close()
			break
		}
	}

	args := []string {"-avd", inst.cfg.Avd}
	if inst.cfg.Kernel != "" {
		args = append(args, "-kernel", inst.cfg.Kernel)
	}

	// arguments before -qemu
	if inst.cfg.AvdArgs == "" {
		// This is reasonable defaults for Android emulator.
		args = append(args,
			"-verbose",
			"-show-kernel",
			"-no-window",
		)
	} else {
		args = append(args, strings.Split(inst.cfg.AvdArgs, " ")...)
	}

	// Bin_Args is following '-qemu' so as not to change its meaning.
	// To change the arguments before -qemu, use Avd_Args
	args = append(args, "-qemu")
	if inst.cfg.BinArgs == "" {
		// This is reasonable defaults for kvm-enabled host.
		args = append(args, "-enable-kvm")
	} else {
		args = append(args, strings.Split(inst.cfg.BinArgs, " ")...)
	}

	// This argument must be added after -qemu
	if inst.cfg.Initrd != "" {
		args = append(args,
			"-initrd", inst.cfg.Initrd,
		)
	}

	if inst.cfg.Debug {
		Logf(0, "running command: %v %#v", inst.cfg.Bin, args)
	}
	qemu := exec.Command(inst.cfg.Bin, args...)
	qemu.Stdout = inst.wpipe
	qemu.Stderr = inst.wpipe
	if err := qemu.Start(); err != nil {
		return fmt.Errorf("failed to start %v %+v: %v", inst.cfg.Bin, args, err)
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.qemu = qemu
	// Qemu has started.

	// Start output merger.
	var tee io.Writer
	if inst.cfg.Debug {
		tee = os.Stdout
	}
	inst.merger = vm.NewOutputMerger(tee)
	inst.merger.Add("qemu", inst.rpipe)
	inst.rpipe = nil

	var bootOutput []byte
	bootOutputStop := make(chan bool)
	go func() {
		for {
			select {
			case out := <-inst.merger.Output:
				bootOutput = append(bootOutput, out...)
			case <-bootOutputStop:
				close(bootOutputStop)
				return
			}
		}
	}()

	// Wait for the qemu asynchronously.
	inst.waiterC = make(chan error, 1)
	go func() {
		err := qemu.Wait()
		inst.waiterC <- err
	}()

	// Wait for device serial number to appear.
	if inst.cfg.Debug {
		Logf(0, "Looking for Android device sn")
	}
	time.Sleep(10 * time.Second)
	start := time.Now()
	for {
		out := string(bootOutput[:])
		if index := strings.Index(out, "emulator: Serial number of this emulator (for ADB):"); index >= 0 {
			if cnt, _ := fmt.Sscanf(out[index:], "emulator: Serial number of this emulator (for ADB): %s\n", &inst.device); cnt == 1 {
				break; // Found device serial number
			}
		}

		select {
		case err := <-inst.waiterC:
			inst.waiterC <- err     // repost it for Close
			time.Sleep(time.Second) // wait for any pending output
			bootOutputStop <- true
			<-bootOutputStop
			return fmt.Errorf("qemu stopped:\n%v\n", string(bootOutput))
		default:
		}
		if time.Since(start) > 10*time.Minute {
			bootOutputStop <- true
			<-bootOutputStop
			return fmt.Errorf("serial number not found: \n%v\n", string(bootOutput))
		}
	}
	bootOutputStop <- true

	if _, err := inst.adb("wait-for-device"); err != nil {
		return fmt.Errorf("wait-for-device: %v", err)
	}
	if _, err := inst.adb("root"); err != nil {
		return fmt.Errorf("adb root failed: %v", err)
	}
	return nil
}

/* Forward port via adb reverse */
func (inst *instance) Forward(port int) (string, error) {
	// If 35099 turns out to be busy, try to forward random ports several times.
	devicePort := port // 35099
	if _, err := inst.adb("reverse", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port)); err != nil {
	      return "", err
						    
	}
	return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
}

func (inst *instance) adb(args ...string) ([]byte, error) {
    args = append([]string{"-s", inst.device}, args...)
    if inst.cfg.Debug {
        Logf(0, "running command: adb %+v", args)
    }
    rpipe, wpipe, err := os.Pipe()
    if err != nil {
        return nil, fmt.Errorf("failed to create pipe: %v", err)
    }
    defer wpipe.Close()
    defer rpipe.Close()
    cmd := exec.Command("adb", args...)
    cmd.Stdout = wpipe
    cmd.Stderr = wpipe
    if err := cmd.Start(); err != nil {
        return nil, err
    }
    wpipe.Close()
    done := make(chan bool)
    go func() {
        select {
        case <-time.After(time.Minute):
		Logf(0, "adb hanged")
		cmd.Process.Kill()
        case <-done:
        }
    }()
    if err := cmd.Wait(); err != nil {
        close(done)
        out, _ := ioutil.ReadAll(rpipe)
        if inst.cfg.Debug {
            Logf(0, "adb failed: %v\n%s", err, out)
        }
        return nil, fmt.Errorf("adb %+v failed: %v\n%s", args, err, out)
    }
    close(done)
    if inst.cfg.Debug {
        Logf(0, "adb returned")
    }
    out, _ := ioutil.ReadAll(rpipe)
    return out, nil
}

/* Copy file via adb push */
func (inst *instance) Copy(hostSrc string) (string, error) {
    vmDst := filepath.Join("/data/local/tmp", filepath.Base(hostSrc))
    if _, err := inst.adb("push", hostSrc, vmDst); err != nil {
        return "", err
    }
    return vmDst, nil
}

/* Run command via adb shell */
func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {

	adbRpipe, adbWpipe, err := vm.LongPipe()
	if err != nil {
		inst.qemu.Process.Kill()
		// Do not close the inst.rpipe 'cause it will be closed in merger
		// inst.rpipe.Close()
		// inst.rpipe = nil
		return nil, nil, err
	}
	
	if inst.cfg.Debug {
		Logf(0, "running command: adb -s %v shell %v", inst.device, command)
	}

	adb := exec.Command("adb", "-s", inst.device, "shell", "cd /data/local/tmp; "+command)	   
	adb.Stdout = adbWpipe
	adb.Stderr = adbWpipe
	if err := adb.Start(); err != nil {
		inst.qemu.Process.Kill()
		// Do not close the inst.rpipe 'cause it will be  closed in merger
		// inst.rpipe.Close()
		adbRpipe.Close()
		adbWpipe.Close()
		return nil, nil, fmt.Errorf("failed to start adb: %v", err)
	    }
	adbWpipe.Close()
	adbDone := make(chan error, 1)
	go func() {
        	err := adb.Wait()
	        if inst.cfg.Debug {
        	    Logf(0, "adb exited: %v", err)
	        }
	        adbDone <- fmt.Errorf("adb exited: %v", err)
	}()

	inst.merger.Add("adb", adbRpipe)

	errc := make(chan error, 1)
	signal := func(err error) {
	       	select {
	        case errc <- err:
        	default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vm.TimeoutErr)
			inst.qemu.Process.Kill()
			adb.Process.Kill()
		case <-stop:
			signal(vm.TimeoutErr)
			inst.qemu.Process.Kill()
			adb.Process.Kill()
		case err := <-adbDone:
			signal(err)
			inst.qemu.Process.Kill()
			//case <-done:
		}
		// Waiting on merger will close the channel
		// inst.merger.Wait()
	}()
	return inst.merger.Output, errc, nil
}


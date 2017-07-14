// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package git provides helper functions for working with git repositories.
package git

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const timeout = time.Hour // timeout for all git invocations

// Poll checkouts the specified repository/branch in dir.
// This involves fetching/resetting/cloning as necessary to recover from all possible problems.
// Returns hash of the HEAD commit in the specified branch.
func Poll(dir, repo, branch string) (string, error) {
	osutil.RunCmd(timeout, dir, "git", "reset", "--hard")
	origin, err := osutil.RunCmd(timeout, dir, "git", "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != repo {
		// The repo is here, but it has wrong origin (e.g. repo in config has changed), re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return "", err
		}
	}
	// Use origin/branch for the case the branch was force-pushed,
	// in such case branch is not the same is origin/branch and we will
	// stuck with the local version forever (git checkout won't fail).
	if _, err := osutil.RunCmd(timeout, dir, "git", "checkout", "origin/"+branch); err != nil {
		// No such branch (e.g. branch in config has changed), re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return "", err
		}
	}
	if _, err := osutil.RunCmd(timeout, dir, "git", "fetch", "--no-tags"); err != nil {
		// Something else is wrong, re-clone.
		if err := clone(dir, repo, branch); err != nil {
			return "", err
		}
	}
	if _, err := osutil.RunCmd(timeout, dir, "git", "checkout", "origin/"+branch); err != nil {
		return "", err
	}
	return HeadCommit(dir)
}

func clone(dir, repo, branch string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	if err := osutil.MkdirAll(dir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	args := []string{
		"clone",
		repo,
		"--single-branch",
		"--branch", branch,
		dir,
	}
	_, err := osutil.RunCmd(timeout, "", "git", args...)
	return err
}

// HeadCommit returns hash of the HEAD commit of the current branch of git repository in dir.
func HeadCommit(dir string) (string, error) {
	output, err := osutil.RunCmd(timeout, dir, "git", "log", "--pretty=format:'%H'", "-n", "1")
	if err != nil {
		return "", err
	}
	if len(output) != 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
	}
	if len(output) != 0 && output[0] == '\'' && output[len(output)-1] == '\'' {
		output = output[1 : len(output)-1]
	}
	if len(output) != 40 {
		return "", fmt.Errorf("unexpected git log output, want commit hash: %q", output)
	}
	return string(output), nil
}

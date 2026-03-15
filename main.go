package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"wrapper/engine"
)

func main() {
	rulesPath := flag.String("rules", "rules/master_rules_v1.json", "Path to rules JSON file")
	targetScript := flag.String("script", "agent.py", "Python script to wrap")
	flag.Parse()

	eng, err := engine.LoadEngine(*rulesPath)
	if err != nil {
		log.Fatalf("Failed to initialize engine: %v", err)
	}
	fmt.Printf("[Wrapper] Loaded %d rules.\n", len(eng.Rules))

	// Prepare the command
	cmd := exec.Command("python", *targetScript)
	cmdArgs := flag.Args()
	if len(cmdArgs) > 0 {
		cmd.Args = append(cmd.Args, cmdArgs...)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout pipe: %v", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to get stderr pipe: %v", err)
	}

	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start %s: %v", *targetScript, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	processOutput := func(r io.Reader, w io.Writer, streamName string) {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				
				// Scan chunk
				res := eng.Scan(string(chunk))
				for _, m := range res.Matches {
					fmt.Fprintf(os.Stderr, "[ALERT] %s match '%s' (Rule: %s, Sev: %s)\n", streamName, m.Match, m.RuleName, m.Severity)
				}
				
				// Pass through output
				w.Write(chunk)
			}
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "[ERROR] %s read error: %v\n", streamName, err)
				}
				break
			}
		}
	}

	go processOutput(stdoutPipe, os.Stdout, "STDOUT")
	go processOutput(stderrPipe, os.Stderr, "STDERR")

	wg.Wait()
	err = cmd.Wait()
	if err != nil {
		fmt.Printf("[Wrapper] Process exited with error: %v\n", err)
	} else {
		fmt.Println("[Wrapper] Process exited cleanly.")
	}
}

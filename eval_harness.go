package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"
)

// DatasetRow represents a single test case in our datasets.
type DatasetRow struct {
	Input    string `json:"input"`
	IsAttack bool   `json:"is_attack"`
}

// EvalResult stores the result of evaluating a single row.
type EvalResult struct {
	Input          string        `json:"input"`
	ExpectedAttack bool          `json:"expected_attack"`
	ActualAttack   bool          `json:"actual_attack"`
	Latency        time.Duration `json:"latency_ns"`
	DatasetFile    string        `json:"dataset_file"`
}

// Report aggregates the evaluation results.
type Report struct {
	TotalProcessed int           `json:"total_processed"`
	TotalAttacks   int           `json:"total_attacks"`
	TotalNormal    int           `json:"total_normal"`
	ASR            float64       `json:"asr_percent"` // Attack Success Rate (True Positives / Total Attacks)
	FPR            float64       `json:"fpr_percent"` // False Positive Rate (False Positives / Total Normal)
	AvgLatency     time.Duration `json:"avg_latency_ns"`
	FalsePositives []EvalResult  `json:"false_positives"` // Normal inputs flagged as attacks
	FalseNegatives []EvalResult  `json:"false_negatives"` // Attacks missed by the engine
}

// MockRuleEngine simulates evaluating an input.
// Replace this with the actual compiled rule engine call.
func MockRuleEngine(input string) bool {
	// Simple mock logic: if it contains "DROP TABLE" or "script", flag as attack.
	// In reality, this would call your Cgo or Wasm rule engine.
	time.Sleep(10 * time.Microsecond) // Simulate latency
	
	// Mock: just random or simple keyword check
	if len(input) > 0 && (input[0] == '<' || input[0] == '\'') {
		return true
	}
	return false
}

func runEvaluation() {
	datasetDir := "references/datasets"
	reportFile := "eval_report.json"

	// Find all JSON files in the dataset directory
	files, err := filepath.Glob(filepath.Join(datasetDir, "*.json"))
	if err != nil {
		log.Fatalf("Error finding datasets: %v", err)
	}

	if len(files) == 0 {
		log.Printf("No JSON datasets found in %s. Creating a mock dataset for testing...", datasetDir)
		err = os.MkdirAll(datasetDir, 0755)
		if err == nil {
			mockData := []DatasetRow{
				{Input: "<script>alert(1)</script>", IsAttack: true},
				{Input: "hello world", IsAttack: false},
				{Input: "' OR 1=1 --", IsAttack: true},
				{Input: "admin", IsAttack: false},
			}
			mockBytes, _ := json.MarshalIndent(mockData, "", "  ")
			ioutil.WriteFile(filepath.Join(datasetDir, "mock_dataset.json"), mockBytes, 0644)
			files = []string{filepath.Join(datasetDir, "mock_dataset.json")}
		}
	}

	report := Report{
		FalsePositives: []EvalResult{},
		FalseNegatives: []EvalResult{},
	}

	var totalLatency time.Duration
	var truePositives, falsePositives, trueNegatives, falseNegatives int

	log.Println("Starting evaluation...")

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			log.Printf("Error reading %s: %v", file, err)
			continue
		}

		var rows []DatasetRow
		if err := json.Unmarshal(data, &rows); err != nil {
			log.Printf("Error parsing JSON in %s: %v", file, err)
			continue
		}

		for _, row := range rows {
			report.TotalProcessed++
			if row.IsAttack {
				report.TotalAttacks++
			} else {
				report.TotalNormal++
			}

			start := time.Now()
			isAttack := MockRuleEngine(row.Input)
			latency := time.Since(start)

			totalLatency += latency

			result := EvalResult{
				Input:          row.Input,
				ExpectedAttack: row.IsAttack,
				ActualAttack:   isAttack,
				Latency:        latency,
				DatasetFile:    file,
			}

			if row.IsAttack && isAttack {
				truePositives++
			} else if !row.IsAttack && !isAttack {
				trueNegatives++
			} else if !row.IsAttack && isAttack {
				falsePositives++
				report.FalsePositives = append(report.FalsePositives, result)
			} else if row.IsAttack && !isAttack {
				falseNegatives++
				report.FalseNegatives = append(report.FalseNegatives, result)
			}
		}
	}

	if report.TotalProcessed > 0 {
		report.AvgLatency = totalLatency / time.Duration(report.TotalProcessed)
	}

	if report.TotalAttacks > 0 {
		report.ASR = (float64(truePositives) / float64(report.TotalAttacks)) * 100
	}

	if report.TotalNormal > 0 {
		report.FPR = (float64(falsePositives) / float64(report.TotalNormal)) * 100
	}

	log.Printf("Evaluation complete. Processed %d rows.", report.TotalProcessed)
	log.Printf("ASR: %.2f%%, FPR: %.2f%%, Avg Latency: %v", report.ASR, report.FPR, report.AvgLatency)

	reportBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling report: %v", err)
	}

	err = ioutil.WriteFile(reportFile, reportBytes, 0644)
	if err != nil {
		log.Fatalf("Error writing report to %s: %v", reportFile, err)
	}

	log.Printf("Detailed report written to %s", reportFile)
}

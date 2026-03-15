package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type RuleDef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
}

type RulesFile struct {
	Rules []RuleDef `json:"rules"`
}

type CompiledRule struct {
	Def RuleDef
	Re  *regexp.Regexp
}

type Engine struct {
	Rules []CompiledRule
}

type Match struct {
	RuleID   string
	RuleName string
	Severity string
	Match    string
}

type Result struct {
	Matches []Match
}

func LoadEngine(rulesPath string) (*Engine, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %v", err)
	}

	var rf RulesFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("failed to parse rules json: %v", err)
	}

	eng := &Engine{}
	for _, r := range rf.Rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern for rule %s: %v", r.ID, err)
		}
		eng.Rules = append(eng.Rules, CompiledRule{
			Def: r,
			Re:  re,
		})
	}

	return eng, nil
}

func (e *Engine) Scan(input string) Result {
	var res Result
	for _, cr := range e.Rules {
		matches := cr.Re.FindAllString(input, -1)
		for _, m := range matches {
			res.Matches = append(res.Matches, Match{
				RuleID:   cr.Def.ID,
				RuleName: cr.Def.Name,
				Severity: cr.Def.Severity,
				Match:    m,
			})
		}
	}
	return res
}

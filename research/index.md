# Research Index

## Cloned Repositories

| Repo | Focus | Key Takeaways |
|------|-------|---------------|
| [InjecAgent](repos/InjecAgent/) | Agent indirect injection benchmark | 1,054 test cases (DH+DS), tool response injection pattern, attack types: Physical Harm, Data Theft |
| [garak](repos/garak/) | LLM vulnerability scanning framework | Hijacking attacks, latent injection separators, DAN/STAN/DUDE markers, encoding templates, Jinja/SQL injection teasers, markdown image exfil, token smuggling |
| [PyRIT](repos/PyRIT/) | Red-teaming automation toolkit | 80+ converters (base64, ROT13, Unicode), SkeletonKey/ManyShot/Flip/Crescendo attacks, negation trap, persuasion-based attacks |
| [PromptBench](repos/promptbench/) | Adversarial robustness evaluation | CheckList (random appending), StressTest (tautology insert), TextBugger (homoglyph substitution), TextFooler (synonym swap) |
| [Inspect AI](repos/inspect_ai/) | AI evaluation platform | Scorer architecture (match, model_graded), task composition pattern, sandbox execution, approval workflows |

## Research-Derived Heuristic Rules

35 new rules added from research (HR-031 to HR-065):

### From garak
- HR-031 to HR-037: Hijacking system messages, latent injection separators, DAN/STAN/DUDE markers, encoding templates, Jinja injection, markdown image exfil, token smuggling

### From PyRIT
- HR-038 to HR-045: Base64/ROT13 wrapping, SkeletonKey pattern, ManyShot long-context, Flip attack, Crescendo escalation, negation trap, persuasion phrases

### From PromptBench
- HR-046 to HR-050: Random text appending, tautology injection, homoglyph substitution, synonym swaps of safety terms, TextFooler character perturbation

### From InjecAgent
- HR-051 to HR-058: Tool response injection pattern, AugustSmartLock exploit, Evernote injection, Amazon review injection, user tool hijack, attacker tool chaining, physical harm indicators, data theft signals

### Novel / Combined
- HR-059 to HR-065: Multi-turn escalation, chain-of-thought poisoning, few-shot injection, XML/JSON boundary crossing, Unicode direction override, invisible character injection, recursive self-reference

## Key Papers & References

| Title | Relevance |
|-------|-----------|
| "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (Greshake et al.) | Foundational indirect injection taxonomy |
| "Prompt Injection Attacks Against LLM-Integrated Applications" (Liu et al.) | Attack surface mapping for agentic systems |
| "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents" (Zhan et al.) | Benchmark methodology we adapted |
| "Jailbreaking Black Box Large Language Models in Twenty Queries" (Chao et al.) | Automated jailbreak generation |
| "Universal and Transferable Adversarial Attacks on Aligned Language Models" (Zou et al.) | GCG suffix attacks |

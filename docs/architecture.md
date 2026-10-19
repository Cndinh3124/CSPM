# Architecture

```text
Terraform -> AWS lab resources
                  |
                  v
           Prowler AWS CLI
           (native checks)
                  |
                  v
         Prowler CSV output
                  |
                  v
       Python: filter status=FAIL
                  |
                  v
      reports/findings_fail.csv
                  |
                  v
          Google Gemini API
       (explain and recommend)
                  |
                  v
       reports/gemini_analysis.md
                  |
                  v
 Human reviews remediation, applies it,
         then runs Prowler again
```

Prowler owns the security checks. Python only orchestrates the command, filters its CSV,
and sends a bounded subset of findings for AI-assisted explanation. Gemini is not given
AWS credentials and cannot perform remediation in this project.

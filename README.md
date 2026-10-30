# iac-audit

A static security audit for **Terraform and CloudFormation**. It reads the templates before
anything is deployed and reports the mistakes that turn into incidents: buckets open to the
internet, security groups admitting `0.0.0.0/0` on RDP and SSH, databases with a public endpoint,
`Action: "*"` on `Resource: "*"`, roles any account can assume, credentials committed in plain
text, and storage that is not encrypted.

```
$ python -m iac_audit examples/vulnerable

IaC audit — 9 resources across 1 file
──────────────────────────────────────────────────────────────────────────────
[CRITICAL] IAC006  IAM policy grants * on *
           aws_iam_policy.admin  examples/vulnerable/main.tf:81
           Action = "*", Resource = "*"

[HIGH]     IAC001  S3 bucket is publicly readable
           aws_s3_bucket.reports  examples/vulnerable/main.tf:8
           acl = public-read

[HIGH]     IAC002  Security group admits the internet
           aws_security_group.bastion  examples/vulnerable/main.tf:28
           ingress 0.0.0.0/0 -> SSH (22)
...
1 Critical, 7 High, 2 Medium, 1 Low across 9 resources
```

Exit status is `1` when a finding at or above `--fail-on` exists, so it drops into a pipeline
without a wrapper script.

## Why it exists

Every cloud incident story starts the same way: the exposure was in the template, reviewed by
three people, and nobody read the `cidr_blocks` line. That is a problem static analysis solves
well and runtime tools solve late.

Most scanners in this space want an account, a credential, and network access. This one reads
files. That makes it safe to run on a pull request, in CI, or on a laptop offline — and it means a
reviewer can see the finding in the diff rather than in a dashboard after deployment.

## Quick start

Requires Python 3.9+. No third-party packages.

```bash
git clone https://github.com/biggjayy2000/iac-audit.git
cd iac-audit

python -m iac_audit examples/vulnerable            # deliberately bad templates
python -m iac_audit examples/clean                 # the same stack, fixed
python -m iac_audit . -f markdown -o report.md     # scan a repository
```

Run the tests:

```bash
python -m unittest discover -s tests -t . -v
```

## Usage

```
python -m iac_audit PATH [PATH ...] [options]

  -f, --format {text,markdown,json}   output format (default: text)
  -o, --output PATH                   write the report to a file
  --fail-on {critical,high,medium,low,none}
                                      exit 1 at or above this severity (default: high)
  --no-color                          disable ANSI colour
```

In CI:

```yaml
- run: python -m iac_audit infra/ --fail-on high
```

The JSON format is stable and intended for tickets or a dashboard:

```bash
python -m iac_audit infra/ -f json | jq '.findings[] | {rule_id, severity, location}'
```

## Rules

| Rule | Severity | Finds |
| --- | --- | --- |
| IAC001 | High | S3 bucket with a public ACL or website configuration |
| IAC002 | Critical–Medium | Security group ingress from `0.0.0.0/0`, graded by the port it exposes |
| IAC003 | Medium | EBS volume without encryption |
| IAC004 | High | RDS instance with `publicly_accessible = true` |
| IAC005 | Medium | RDS storage without encryption |
| IAC006 | Critical | IAM policy granting `*` on `*` |
| IAC007 | High | IAM role trusting `Principal: "*"` with no condition |
| IAC008 | High | Credential written into the template |
| IAC009 | Low | EC2 instance assigned a public IP |
| IAC010 | High | S3 bucket policy granting any principal |

Severity follows what an attacker gains, not how clever the check was. A bucket readable by the
internet is High whether it got that way through an ACL, a bucket policy, or website hosting —
which is why three different rules return the same severity rather than inventing a scale per
check.

Port grading in IAC002 is the one place where a rule produces a range. `0.0.0.0/0` on
`-1`/all protocols is Critical, a single administrative port (SSH, RDP, SMB, a database port) is
High, and an ordinary port is Medium. A rule that called every open port Critical would be
technically defensible and practically useless, because it would rank a public web server
alongside an exposed domain controller.

## Design notes

**One rule set, two template languages.** Terraform and CloudFormation describe the same
resources with different names (`acl` vs `AccessControl`, `public-read` vs `PublicRead`). Both are
normalized into a `Resource` with a language-neutral `kind`, so each rule is written once. The
CloudFormation example exists partly to keep that honest: writing it surfaced a real bug where
the ACL rule only matched Terraform's spelling of `public-read`.

**The HCL reader is deliberately small.** It is not a general HCL2 implementation. It reads
blocks, labels, attributes, lists, maps, heredocs and `jsonencode` payloads, and keeps anything it
cannot evaluate — a reference, an interpolation, a function call — as an opaque string. A rule
that silently misreads `var.bucket_acl` as "not public" is worse than one that stays quiet, so
unresolved values never match a check.

**Secrets are never printed.** IAC008 reports the attribute name and the line, and masks the
value. A scanner that echoes a credential into a report has moved it somewhere new, and that
report gets attached to a ticket.

**Policy documents are parsed, not pattern-matched.** `jsonencode(...)` payloads are decoded and
the statements walked, so `Effect`, `Principal`, `Action` and `Resource` are read as data. A
grep for `"*"` would flag a `Resource` ARN that happens to contain a wildcard and miss a policy
assembled from variables.

## Limits

- Static analysis only. It reads what is written, not what Terraform will build after variables,
  modules and providers are resolved. A bucket whose ACL comes from a variable is not reported.
- AWS resources only. The rules encode CIS AWS benchmarks; Azure and GCP would need their own
  mapping, not a find-and-replace.
- No custom rule loading yet. That is the obvious next step: a rules file per organisation, since
  every company has two or three house rules that matter more than the generic ones.
- Module inputs are not followed. A module that creates a public bucket reports nothing at the
  call site.

## Scope

This audits configuration files. It makes no network requests and needs no cloud credentials.
Point it at repositories you are responsible for.

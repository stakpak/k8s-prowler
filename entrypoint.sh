#!/bin/bash
set -e


./prowler "$@" -z -b -M json -F report

# mapping Critical -> high due to https://github.com/kyverno/kyverno/issues/4324
# mapping Inormational -> low due to https://github.com/kyverno/kyverno/issues/4324
jq -s '
def severity_mapping: {
    "Critical": "high",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "low",
};
def status_mapping: {
    "FAIL": "fail",
    "PASS": "pass",
    "INFO": "skip",
    "WARNING": "warn",
};
def counter(stream):
  reduce stream as $s ({}; .[$s|tostring] += 1);
map({ 
    source: "Prowler", 
    result: (."Status" |=  status_mapping[.])."Status", 
    scored: true, 
    category: ."Service",
    policy: ."Level", 
    rule: ."Control",
    message: ."Message", 
    timestamp:  {
        seconds: (."Timestamp" |= fromdateiso8601)."Timestamp", 
        nanos: 0
    },
    severity:  (."Severity" |=  severity_mapping[.])."Severity", 
    properties: { 
        controlID: ."Control ID", 
        region: ."Region", 
        service: ."Service", 
        accountNumber: ."Account Number", 
        risk: ."Risk", 
        remediation: ."Remediation", 
        resourceID: ."Resource ID", 
        cafEpic: ."CAF Epic", 
        docLink: ."Doc link", 
        compliance: ."Compliance"  
    } 
}) | 
{
    apiVersion: "wgpolicyk8s.io/v1alpha2",
    kind: "ClusterPolicyReport",
    metadata: {
        name: "prowler-report",
        labels: {
        },
    },
    summary: ({pass: 0, warn: 0, error: 0, skip: 0, fail: 0} * counter(.[] | .result)),
    results: .
}
' /prowler/output/report.json > cluster-policy-report.json

# cannot use apply, this will exceed maximum allowed annotation length for large reports
./kubectl replace -f cluster-policy-report.json || ./kubectl create -f cluster-policy-report.json

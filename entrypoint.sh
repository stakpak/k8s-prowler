#!/bin/bash
set -e


./prowler "$@" -z -q -b -M json -F report

jq -s '
map({ 
    source: "Prowler", 
    result: "fail", 
    scored: true, 
    category: ."Service",
    policy: ."Control", 
    message: ."Message", 
    timestamp:  {
        seconds: (."Timestamp" |= fromdateiso8601)."Timestamp", 
        nanos: 0
    },
    severity: (."Severity" |= ascii_downcase)."Severity", 
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
    summary: {
        fail: (. | length)
    },    
    results: .
}
' /prowler/output/report.json > cluster-policy-report.json

./kubectl apply -f cluster-policy-report.json
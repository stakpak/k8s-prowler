# k8s-prowler


## Setup

You have to add IRSA permissions to allow prowler to scan your account

1) Initialize variables
```
ACCOUNT_ID="111122223333"
CLUSTER_NAME="demo"
NAMESPACE="prowler-namespace"
SERVICE_ACCOUNT="prowler"
```

2) Get cluster OIDC provider
```
OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")
```

3) Create trust relationship policy
```
read -r -d '' TRUST_RELATIONSHIP <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com",
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}"
        }
      }
    }
  ]
}
EOF

echo "${TRUST_RELATIONSHIP}" > trust.json
```

4) Create role
```
aws iam create-role --role-name prowler --assume-role-policy-document file://trust.json --description "prowler scanner IAM Role"
```

5) Attach policies to role
```
aws iam attach-role-policy --role-name prowler --policy-arn=arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name prowler --policy-arn=arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
```

6) Install the chart!
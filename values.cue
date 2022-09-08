#AWSRegions:
	"ap-south-1" |
	"eu-west-3" |
	"eu-north-1" |
	"eu-west-2" |
	"eu-west-1" |
	"ap-northeast-3" |
	"ap-northeast-2" |
	"ap-northeast-1" |
	"sa-east-1" |
	"ca-central-1" |
	"ap-southeast-1" |
	"ap-southeast-2" |
	"eu-central-1" |
	"us-east-1" |
	"us-east-2" |
	"us-west-1" |
	"us-west-2" |
	"cn-north-1" |
	"cn-northwest-1"

#ProwlerGroupChecks:
	"group1" |
	"group2" |
	"group3" |
	"group4" |
	"cislevel1" |
	"cislevel2" |
	"extras" |
	"forensics-ready" |
	"gdpr" |
	"hipaa" |
	"secrets" |
	"apigateway" |
	"rds" |
	"elasticsearch" |
	"pci" |
	"trustboundaries" |
	"internet-exposed" |
	"iso27001" |
	"eks-cis" |
	"ffiec" |
	"soc2" |
	"sagemaker" |
	"ens" |
	"glue" |
	"ftr" |
	"ds"

#Image: {
	repository: string
	pullPolicy: string & ("IfNotPresent" | "Always")
	tag:        string
}

#Prowler: {
	accountID:    =~"^\\d{12}$"
	roleName:     string
	region:       #AWSRegions
	groupCheck:   null | #ProwlerGroupChecks
	cronSchedule: string
}

image:   #Image
prowler: #Prowler

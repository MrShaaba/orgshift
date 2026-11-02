module github.com/MrShaaba/orgshift

go 1.24.0

require (
	github.com/aws/aws-sdk-go-v2 v1.47.5
	github.com/aws/aws-sdk-go-v2/config v1.33.13
	github.com/aws/aws-sdk-go-v2/credentials v1.20.13
	github.com/aws/aws-sdk-go-v2/service/account v1.42.7
	github.com/aws/aws-sdk-go-v2/service/controlcatalog v1.25.2
	github.com/aws/aws-sdk-go-v2/service/controltower v1.38.3
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.49.5
	github.com/aws/aws-sdk-go-v2/service/organizations v1.62.4
	github.com/aws/aws-sdk-go-v2/service/ram v1.45.8
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.1
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.52.2
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.1
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.6
	github.com/aws/smithy-go v1.28.7
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.1 // indirect
)

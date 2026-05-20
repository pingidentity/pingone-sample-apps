module p1-login-flow

go 1.25.6

require (
	github.com/joho/godotenv v1.5.1
	github.com/pingidentity/pingone-go-client v0.0.0-00010101000000-000000000000
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/zalando/go-keyring v0.2.6 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/pingidentity/pingone-go-client => ../pingone-go-client

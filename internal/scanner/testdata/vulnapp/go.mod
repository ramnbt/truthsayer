module example.com/vulnapp

go 1.25

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	golang.org/x/crypto v0.27.0
)

require github.com/cloudflare/circl v1.3.9 // indirect

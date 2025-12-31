# ATP
Azzurro Technical Platform (ATP) is a lightweight data platform prototype. It consists of a pure Go server that uses only the standard library, an HTML5 UI rendered with Go templates, a single CSS stylesheet, and vanilla JavaScript that runs in any modern browser. The UI allows creation of reusable form templates, adding them to the workspace as articles, searching and filtering fields, persisting field values locally, encrypting the workspace on the client, and synchronizing encrypted contexts with the server. Authentication is rate‑limited to prevent brute‑force attacks. The project includes Docker and Caddy configurations for containerised deployment with automatic HTTPS.

Prerequisites
Go version 1.22 or newer
A modern web browser with Web Crypto API support

Building and running locally
go mod tidy
go build -o atp-server ./server/main.go
./atp-server
The server listens on http://localhost:8080

Running with Docker
docker build -t atp:latest .
docker run -p 8080:8080 --rm atp:latest

Running with Docker Compose (includes Caddy reverse proxy and automatic TLS)
docker compose up -d

Features
Form library with reusable templates
Workspace with nested articles, delete, expand and add child controls
Keyword based ads displayed in an aside element
Search bar that filters articles by label, placeholder or input name
Automatic persistence of field values in localStorage
Client side encryption using AES‑GCM
Manual export and import of workspace as JSON
Authenticated upload and download of encrypted contexts
Rate limited login and registration endpoints
Mobile responsive layout
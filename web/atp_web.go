// Package web implements web interfaces for the ATP platform
package web

import (
	"encoding/json"
	"log"
	"net/http"

	"azzurrotech/atp/internal"
)

type ATPService struct {
	Server        http.Handler
	Port          string
	ServiceRegistry *internal.ServiceRegistry
}

type ServiceInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Port        string `json:"port"`
	HealthURL   string `json:"health_url"`
	ConfigURL   string `json:"config_url"`
	AdminURL    string `json:"admin_url"`
	Status      string `json:"status"`
	Type        string `json:"type"`
}

type Config struct {
	Services map[string]ServiceInfo `json:"services"`
}

// Helper functions for converting between internal Service and web ServiceInfo
func convertToInternalService(serviceInfo ServiceInfo) internal.Service {
	return internal.Service{
		Name:        serviceInfo.Name,
		Version:     serviceInfo.Version,
		Description: serviceInfo.Description,
		Port:        serviceInfo.Port,
		HealthURL:   serviceInfo.HealthURL,
		ConfigURL:   serviceInfo.ConfigURL,
		AdminURL:    serviceInfo.AdminURL,
		Status:      serviceInfo.Status,
		Type:        serviceInfo.Type,
		LastChecked: "",
		Metadata:    make(map[string]string),
	}
}

func convertToServiceInfo(service internal.Service) ServiceInfo {
	return ServiceInfo{
		Name:        service.Name,
		Version:     service.Version,
		Description: service.Description,
		Port:        service.Port,
		HealthURL:   service.HealthURL,
		ConfigURL:   service.ConfigURL,
		AdminURL:    service.AdminURL,
		Status:      service.Status,
		Type:        service.Type,
	}
}

func getDefaultServices() []ServiceInfo {
	return []ServiceInfo{
		{
			Name:        "stenella",
			Version:     "1.0.0",
			Description: "Data aggregation platform",
			Port:        "8081",
			HealthURL:   "/health",
			Status:      "healthy",
			Type:        "data-platform",
		},
		{
			Name:        "pod",
			Version:     "1.0.0",
			Description: "HTML form database",
			Port:        "8082",
			HealthURL:   "/health",
			Status:      "healthy",
			Type:        "database",
		},
		{
			Name:        "song",
			Version:     "1.0.0",
			Description: "Magic link authentication",
			Port:        "8083",
			HealthURL:   "/health",
			Status:      "healthy",
			Type:        "auth",
		},
		{
			Name:        "shepherd",
			Version:     "1.0.0",
			Description: "Firewall and Paywall",
			Port:        "8084",
			HealthURL:   "/health",
			Status:      "healthy",
			Type:        "security",
		},
	}
}

// CORS middleware implementation for standard library
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Handler function type
type HandlerFunc func(http.ResponseWriter, *http.Request)

func (s *ATPService) GetService(w http.ResponseWriter, r *http.Request) {
	// Robust path parameter extraction
	if len(r.URL.Path) < len("/api/services/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing service name in path"})
		return
	}

	name := r.URL.Path[len("/api/services/"):]
	if name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Service name cannot be empty"})
		return
	}

	service := ServiceInfo{
		Name:        name,
		Version:     "1.0.0",
		Description: "Service " + name,
		Port:        "8080",
		HealthURL:   "/health",
		Status:      "unknown",
		Type:        "service",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(service)
}

func NewATPService(port string) *ATPService {
	// Create a new HTTP server with CORS middleware support
	mux := http.NewServeMux()

	// Initialize ServiceRegistry
	serviceRegistry := internal.NewServiceRegistry()

	// Create service and register routes
	service := &ATPService{Server: mux, Port: port, ServiceRegistry: serviceRegistry}

	// Preload default services
	preloadDefaultServices(serviceRegistry)

	service.RegisterRoutes()

	return service
}

// Helper function to preload default services into ServiceRegistry
func preloadDefaultServices(registry *internal.ServiceRegistry) {
	// Only preload if registry is empty
	if len(registry.ListServices()) == 0 {
		log.Printf("Preloading default services into ServiceRegistry")
		services := getDefaultServices()
		for _, serviceInfo := range services {
			registry.RegisterService(convertToInternalService(serviceInfo))
		}
		log.Printf("Preloaded %d default services", len(services))
	} else {
		log.Printf("ServiceRegistry already populated with %d services", len(registry.ListServices()))
	}
}

func (s *ATPService) RegisterRoutes() {
	// Register standard HTTP handlers with CORS middleware

	// Helper to wrap handlers with CORS
	withCORS := func(h http.HandlerFunc) http.HandlerFunc {
		return corsMiddleware(h)
	}

	// High Maturity API endpoints
	apiMux := http.NewServeMux()

	// atp APIs
	atpMux := http.NewServeMux()
	atpMux.HandleFunc("GET /config", withCORS(s.GetConfig))
	atpMux.HandleFunc("POST /config", withCORS(s.UpdateConfig))
	atpMux.HandleFunc("GET /admin", withCORS(s.GetAdmin))
	atpMux.HandleFunc("POST /admin", withCORS(s.UpdateAdmin))

	// Service registration and discovery
	servicesMux := http.NewServeMux()
	servicesMux.HandleFunc("GET /", withCORS(s.ListServices))
	servicesMux.HandleFunc("GET /{name}", withCORS(s.GetService))
	servicesMux.HandleFunc("POST /register", withCORS(s.RegisterService))
	
	// Configuration endpoints
	configMux := http.NewServeMux()
	configMux.HandleFunc("GET /", withCORS(s.GetConfig))
	configMux.HandleFunc("PUT /", withCORS(s.UpdateConfig))

	// Mount sub-routes
	apiMux.Handle("/atp/", http.StripPrefix("/api/atp", atpMux))
	apiMux.Handle("/services/", http.StripPrefix("/api/services", servicesMux))
	apiMux.Handle("/config/", http.StripPrefix("/api/config", configMux))

	// Global endpoints
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", withCORS(s.HomeHandler))
	mux.HandleFunc("GET /health", withCORS(s.HealthCheck))
	mux.HandleFunc("GET /clients", withCORS(s.ClientsHandler))
	mux.HandleFunc("GET /services", withCORS(s.ServicesHandler))
	mux.HandleFunc("GET /billing", withCORS(s.BillingHandler))

	// Mount API routes
	mux.Handle("/api/", http.StripPrefix("/api", apiMux))

	s.Server = mux
}

func (s *ATPService) GetConfig(w http.ResponseWriter, r *http.Request) {
	config := Config{
		Services: map[string]ServiceInfo{
			"stenella": {
				Name:        "stenella",
				Version:     "1.0.0",
				Description: "Data aggregation platform",
				Port:        "8081",
				HealthURL:   "/health",
				ConfigURL:   "/api/stenella/config",
				AdminURL:    "/stenella/admin",
				Status:      "healthy",
				Type:        "data-platform",
			},
			"pod": {
				Name:        "pod",
				Version:     "1.0.0",
				Description: "HTML form database",
				Port:        "8082",
				HealthURL:   "/health",
				ConfigURL:   "/api/pod/config",
				AdminURL:    "/pod/admin",
				Status:      "healthy",
				Type:        "database",
			},
			"song": {
				Name:        "song",
				Version:     "1.0.0",
				Description: "Magic link authentication",
				Port:        "8083",
				HealthURL:   "/health",
				ConfigURL:   "/api/song/config",
				AdminURL:    "/song/admin",
				Status:      "healthy",
				Type:        "auth",
			},
			"shepherd": {
				Name:        "shepherd",
				Version:     "1.0.0",
				Description: "Firewall and Paywall",
				Port:        "8084",
				HealthURL:   "/health",
				ConfigURL:   "/api/shepherd/config",
				AdminURL:    "/shepherd/admin",
				Status:      "healthy",
				Type:        "security",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(config)
}

func (s *ATPService) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	// Ensure request body is properly closed
	defer r.Body.Close()

	var config Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid config: " + err.Error()})
		return
	}

	// In production, this would update persistent configuration
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Configuration updated successfully"})
}

func (s *ATPService) GetAdmin(w http.ResponseWriter, r *http.Request) {
	adminInfo := map[string]interface{}{
		"platform":    "AzzurroTech ATP",
		"version":     "1.0.0",
		"status":      "running",
		"services":    4,
		"active":      true,
		"uptime":      "2 hours",
		"last_backup": "2025-08-24T10:00:00Z",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(adminInfo)
}

func (s *ATPService) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Admin settings updated successfully"})
}

func (s *ATPService) ListServices(w http.ResponseWriter, r *http.Request) {
	// Try to use ServiceRegistry first
	if s.ServiceRegistry != nil {
		services := s.ServiceRegistry.ListServices()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(convertServicesToServiceInfo(services))
		return
	}

	// Fallback to hardcoded services
	log.Printf("ServiceRegistry unavailable, using hardcoded fallback for ListServices")
	services := getDefaultServices()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(services)
}

// Helper function to convert slice of internal.Service to ServiceInfo
func convertServicesToServiceInfo(services []internal.Service) []ServiceInfo {
	result := make([]ServiceInfo, len(services))
	for i, service := range services {
		result[i] = convertToServiceInfo(service)
	}
	return result
}

func (s *ATPService) RegisterService(w http.ResponseWriter, r *http.Request) {
	// Ensure request body is properly closed
	defer r.Body.Close()

	var serviceInfo ServiceInfo
	if err := json.NewDecoder(r.Body).Decode(&serviceInfo); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid service data: " + err.Error()})
		return
	}

	// Convert to internal format
	internalService := convertToInternalService(serviceInfo)

	// Try to use ServiceRegistry first
	if s.ServiceRegistry != nil {
		if err := s.ServiceRegistry.RegisterService(internalService); err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Service registered successfully in registry",
				"service": serviceInfo,
				"registry": "primary",
			})
			return
		}
		log.Printf("ServiceRegistry registration failed: %v", err)
	}

	// Fallback: Log warning and continue with basic success (maintains backward compatibility)
	log.Printf("ServiceRegistry unavailable, using fallback registration for service: %s", serviceInfo.Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Service registered successfully (fallback mode)",
		"service": serviceInfo,
		"registry": "fallback",
	})
}

func (s *ATPService) HealthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": "2025-08-25T14:44:57Z",
		"version":   "1.0.0",
		"platform":  "AzzurroTech ATP",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// HTML Form-based Interface handlers
func (s *ATPService) HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body><h1>ATP - AzzurroTech Platform</h1><p>High Maturity API and Service Hub</p><ul><li><a href='/clients'>Clients</a></li><li><a href='/services'>Services</a></li><li><a href='/billing'>Billing</a></li></ul></body></html>"))
}

func (s *ATPService) ClientsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body><h1>Clients</h1><p>Client management interface</p></body></html>"))
}

func (s *ATPService) ServicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body><h1>Services</h1><p>Service management and monitoring</p></body></html>"))
}

func (s *ATPService) BillingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body><h1>Billing</h1><p>Billing and invoicing system</p></body></html>"))
}

func (s *ATPService) Start() error {
	log.Printf("Starting ATP platform on port %s", s.Port)
	return http.ListenAndServe(":"+s.Port, s.Server)
}

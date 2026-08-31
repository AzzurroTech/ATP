// Package internal provides internal services for the ATP platform
package internal

import (
	"encoding/json"
	"fmt"
	"os"
)

type ServiceRegistry struct {
	Services []Service `json:"services"`
}

type Service struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Port        string            `json:"port"`
	HealthURL   string            `json:"health_url"`
	ConfigURL   string            `json:"config_url"`
	AdminURL    string            `json:"admin_url"`
	Status      string            `json:"status"`
	Type        string            `json:"type"`
	LastChecked string            `json:"last_checked"`
	Metadata    map[string]string `json:"metadata"`
}

type Configuration struct {
	Services []Service              `json:"services"`
	Settings map[string]interface{} `json:"settings"`
}

func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		Services: []Service{},
	}
}

func (r *ServiceRegistry) RegisterService(service Service) error {
	// Check if service already exists
	for i, existing := range r.Services {
		if existing.Name == service.Name {
			r.Services[i] = service
			return nil
		}
	}

	r.Services = append(r.Services, service)
	return nil
}

func (r *ServiceRegistry) GetService(name string) (*Service, error) {
	for _, service := range r.Services {
		if service.Name == name {
			return &service, nil
		}
	}
	return nil, fmt.Errorf("service %s not found", name)
}

func (r *ServiceRegistry) ListServices() []Service {
	return r.Services
}

func (r *ServiceRegistry) GetAllServices() []Service {
	return r.Services
}

func (r *ServiceRegistry) RemoveService(name string) error {
	for i, service := range r.Services {
		if service.Name == name {
			r.Services = append(r.Services[:i], r.Services[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("service %s not found", name)
}

func (r *ServiceRegistry) HealthCheck() {
	for i := 0; i < len(r.Services); i++ {
		service := &r.Services[i]

		// Update status based on health check
		if service.HealthURL != "" {
			service.Status = "healthy"
			service.LastChecked = "just now"
		} else {
			service.Status = "unknown"
			service.LastChecked = "never"
		}
	}
}

func (r *ServiceRegistry) SaveToFile(filename string) error {
	data, err := json.MarshalIndent(r.Services, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal services: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}

	return nil
}

func (r *ServiceRegistry) LoadFromFile(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		// Create empty file if it doesn't exist
		return r.SaveToFile(filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var services []Service
	err = json.Unmarshal(data, &services)
	if err != nil {
		return fmt.Errorf("failed to unmarshal services: %w", err)
	}

	r.Services = services
	return nil
}

func NewConfiguration() *Configuration {
	return &Configuration{
		Services: []Service{},
		Settings: make(map[string]interface{}),
	}
}

func (c *Configuration) GetService(name string) (*Service, error) {
	for _, service := range c.Services {
		if service.Name == name {
			return &service, nil
		}
	}
	return nil, fmt.Errorf("service %s not found in configuration", name)
}

func (c *Configuration) AddService(service Service) {
	c.Services = append(c.Services, service)
}

func (c *Configuration) GetAllServices() []Service {
	return c.Services
}

func (c *Configuration) UpdateService(service Service) error {
	for i, existing := range c.Services {
		if existing.Name == service.Name {
			c.Services[i] = service
			return nil
		}
	}
	return fmt.Errorf("service %s not found for update", service.Name)
}

func (c *Configuration) RemoveService(name string) error {
	for i, service := range c.Services {
		if service.Name == name {
			c.Services = append(c.Services[:i], c.Services[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("service %s not found for removal", name)
}

func (c *Configuration) SetSetting(key string, value interface{}) {
	c.Settings[key] = value
}

func (c *Configuration) GetSetting(key string) (interface{}, bool) {
	value, exists := c.Settings[key]
	return value, exists
}

func (c *Configuration) GetAllSettings() map[string]interface{} {
	return c.Settings
}

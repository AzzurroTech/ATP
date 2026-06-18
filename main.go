package main

import (
	"html/template"
	"net/http"
)

type Component struct {
	Name        string
	Description string
	Port        string
	Link        string
}

func main() {
	components := []Component{
		{Name: "launch", Description: "Docker Compose generator & orchestrator", Port: "8081", Link: "http://localhost:8081"},
		{Name: "pod", Description: "HTML form database & query engine", Port: "8082", Link: "http://localhost:8082"},
		{Name: "vici", Description: "Card-based timeline & lore builder", Port: "8083", Link: "http://localhost:8083"},
		{Name: "vidi", Description: "Visual HTML template generator", Port: "8084", Link: "http://localhost:8084"},
		{Name: "veni", Description: "Visual web crawler & link mapper", Port: "8085", Link: "http://localhost:8085"},
		{Name: "shepherd", Description: "Universal network & AI firewall", Port: "8086", Link: "http://localhost:8086"},
		{Name: "song", Description: "HATEOAS stateless API generator", Port: "8087", Link: "http://localhost:8087"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles("templates/index.html"))
		tmpl.Execute(w, components)
	})

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(":8080", nil)
}

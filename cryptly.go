package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"errors"
	"github.com/ant0ine/go-json-rest/rest"
	"net/http"
)

func main() {
	handler := rest.ResourceHandler{
		EnableRelaxedContentType: true,
	}
	handler.SetRoutes(
		&rest.Route{"POST", "/hash/bcrypt", Hash},
	)
	http.ListenAndServe(":8080", &handler)
}

// JSON payload a user must send to the API service when requesting a password
// hash.
type HashRequest struct {
	Type     string `json:"type"`
	Password string `json:"password"`
	Cost     int    `json:"cost"`
}

// JSON payload returned to a user after successfully computing a password
// hash.
type HashResponse struct {
	Hash string `json:"hash"`
}

// Generate a password hash.
func Hash(w rest.ResponseWriter, r *rest.Request) {

	// First, we'll attempt to read in the user's body as JSON so we can figure
	// out what the user wants.
	hr := HashRequest{}
	err := r.DecodeJsonPayload(&hr)

	// Throw an error if the JSON payload couldn't be decoded.
	if err != nil {
		rest.Error(w, "Could not decode JSON data.", http.StatusBadRequest)
		return
	}

	// Ensure the user has specified a value for the type field.
	if hr.Type == "" {
		rest.Error(w, "The type field is required.", http.StatusBadRequest)
		return
	}

	// Ensure the user has specified a value for the password field.
	if hr.Password == "" {
		rest.Error(w, "The password field is required.", http.StatusBadRequest)
		return
	}

	// The response we'll eventually send back to the user.
	var hresp *HashResponse

	// Compute the hash of the specified type.
	switch hr.Type {
	case "bcrypt":
		hresp, err = GenerateBcryptHash(&hr)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusInternalServerError)
		}
	default:
		rest.Error(w, "Invalid type specified.", http.StatusBadRequest)
	}

	// Send our response to the user.
	w.WriteJson(&hresp)

}

// Generate a bcrypt hash given a password.
func GenerateBcryptHash(hr *HashRequest) (*HashResponse, error) {

	// If the user specified no cost (or a cost smaller than the minimum
	// allowed), we'll automatically set the cost to the bcrypt library's
	// recommended value.
	if hr.Cost < bcrypt.MinCost {
		hr.Cost = bcrypt.DefaultCost
	}

	// Compute the bcrypt password hash.  This might take a while if the cost is
	// high.
	hash, err := bcrypt.GenerateFromPassword([]byte(hr.Password), hr.Cost)
	if err != nil {
		return nil, errors.New("Could not compute the bcrypt password hash.")
	}

	// Send our response to the user.
	hresp := HashResponse{Hash: string(hash)}
	return &hresp, nil

}

package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"errors"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/dchest/uscrypt"
	"github.com/imdario/mergo"
	"net/http"
)

func main() {
	handler := rest.ResourceHandler{
		EnableRelaxedContentType: true,
	}
	handler.SetRoutes(
		&rest.Route{"POST", "/hash", Hash},
	)
	http.ListenAndServe(":8080", &handler)
}

// JSON payload a user must send to the API service when requesting a password
// hash.
type HashRequest struct {
	Type     string              `json:"type"`
	Password string              `json:"password"`
	Options  *HashRequestOptions `json:"options"`
}

// This struct contains all possible hashing options for the various hashing
// algorithms.  These fields can be specified in a hash request by a developer
// to control specific algorithm behavior.  In general, I don't recommend users
// overriding these values unless they're absolutely certain they know what
// they're doing.
type HashRequestOptions struct {
	Cost     int `json:"cost"`
	N        int `json:"n"`
	R        int `json:"r"`
	P        int `json:"p"`
	SaltSize int `json:"salt_size"`
	HashSize int `json:"hash_size"`
}

// JSON payload returned to a user after successfully computing a password
// hash.
type HashResponse struct {
	Hash string `json:"hash"`
}

// A fully populated HashRequestOptions struct with all default values
// set.  These are the 'recommended' values that will be used for all
// non-overridden requests.
var DefaultHashRequestOptions = HashRequestOptions{
	Cost:     14,
	N:        14,
	R:        8,
	P:        1,
	SaltSize: 32,
	HashSize: 32,
}

// Generate a password hash.
func Hash(w rest.ResponseWriter, r *rest.Request) {

	// The response we'll eventually send back to the user.
	var hresp *HashResponse
	var err error

	// First, we'll attempt to read in the user's body as JSON so we can figure
	// out what the user wants.
	hr := HashRequest{}

	// Throw an error if the JSON payload couldn't be decoded.
	if err = r.DecodeJsonPayload(&hr); err != nil {
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

	// If no options were specified, use the defaults!
	if hr.Options == nil {
		hr.Options = &DefaultHashRequestOptions
	}

	// Compute the hash of the specified type.
	switch hr.Type {
	case "bcrypt":
		if hresp, err = GenerateBcryptHash(&hr); err != nil {
			rest.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "scrypt":
		if hresp, err = GenerateScryptHash(&hr); err != nil {
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

	// First, grab the hash options and either use what the user specified or
	// set them to the defaults (recommended).
	if err := mergo.Merge(hr.Options, DefaultHashRequestOptions); err != nil {
		return nil, errors.New("Invalid options specified.")
	}

	// If the user specified no cost (or a cost smaller than the minimum
	// allowed), we'll automatically set the cost to the bcrypt library's
	// recommended value.
	if hr.Options.Cost < bcrypt.MinCost {
		hr.Options.Cost = bcrypt.DefaultCost
	}

	// Compute the bcrypt password hash.
	hash, err := bcrypt.GenerateFromPassword([]byte(hr.Password), hr.Options.Cost)
	if err != nil {
		return nil, errors.New("Could not compute the bcrypt password hash.")
	}

	// Send our response to the user.
	return &HashResponse{Hash: string(hash)}, nil

}

// Generate a scrypt hash given a password.
func GenerateScryptHash(hr *HashRequest) (*HashResponse, error) {

	// First, grab the hash options and either use what the user specified or
	// set them to the defaults (recommended).
	if err := mergo.Merge(hr.Options, DefaultHashRequestOptions); err != nil {
		return nil, errors.New("Invalid options specified.")
	}

	// Build our scrypt config.
	config := uscrypt.Config{
		LogN:     int8(hr.Options.N),
		R:        hr.Options.R,
		P:        hr.Options.P,
		SaltSize: hr.Options.SaltSize,
		HashSize: hr.Options.HashSize,
	}

	// Compute the scrypt password hash.
	hash, err := uscrypt.HashPassword([]byte(hr.Password), &config)
	if err != nil {
		return nil, errors.New("Could not compute the scrypt password hash.")
	}

	// Send our response to the user.
	return &HashResponse{Hash: hash}, nil

}

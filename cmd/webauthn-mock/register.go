package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/fxamacker/cbor/v2"
	"github.com/fxamacker/webauthn"
	_ "github.com/fxamacker/webauthn/packed"
)

const (
	WebauthnDisplayName = "Smooth Keys"
	WebauthnDomain      = "smoo.th"
	WebauthnOrigin      = "https://smoo.th"
	DefaultUserID       = "DlmvvsemRs-uJJKZGgf_lg"
	DefaultUserName     = "qdqd"
)

var webauthnConfig = webauthn.Config{
	RPID:                    WebauthnDomain,
	RPName:                  WebauthnDisplayName,
	Timeout:                 uint64(60000),
	ChallengeLength:         64,
	UserVerification:        webauthn.UserVerificationRequired,
	Attestation:             webauthn.AttestationNone,
	CredentialAlgs:          []int{webauthn.COSEAlgES256},
	AuthenticatorAttachment: webauthn.AuthenticatorPlatform,
}

type User struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

type WebauthnAttestation struct {
	User      *webauthn.User
	Challenge []byte
	Options   string
}

type FullClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}
type WebauthnResponse struct {
	Id       string `json:"id,omitempty"`
	RawId    string `json:"rawId,omitempty"`
	Response struct {
		AttestationObject string `json:"attestationObject,omitempty"`
		ClientDataJSON    string `json:"clientDataJSON,omitempty"`
	}
}

type attestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}
type attestationStatementClean struct {
	Algorithm int    `json:"alg"`
	Signature string `json:"sig"`
}
type attestationObject struct {
	Format    string               `json:"fmt"`
	Statement attestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type FullAttestationObject struct {
	Raw64     string                    `json:"raw64,omitempty"`
	Format    string                    `json:"fmt"`
	Statement attestationStatementClean `json:"attStmt"`
	AuthData  string                    `json:"authData"`
}

type WebauthnResponseComplete struct {
	Id                string `json:"id,omitempty"`
	RawId             string `json:"rawId,omitempty"`
	AttestationObject FullAttestationObject
	ClientDataJSON    FullClientData
}

type WebAuthnResponseRaw struct {
	AttestationObject string `json:"AttestationObject,omitempty"`
	ClientDataJSON    string `json:"clientDataJSON,omitempty"`
}

type WebAuthnRegister struct {
	WebauthnUser             User                                `json:"user,omitempty"`
	WebauthnConfig           webauthn.Config                     `json:"config,omitempty"`
	WebauthnOptions          *virtualwebauthn.AttestationOptions `json:"options,omitempty"`
	WebauthnResponseComplete WebauthnResponseComplete            `json:"responseDecoded,omitempty"`
	WebAuthnResponseRaw      WebAuthnResponseRaw                 `json:"response,omitempty"`
}

func register(challenge string, username string) (*virtualwebauthn.AttestationOptions, string) {
	// Create a new EC2 credential for the user
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// The relying party settings should mirror those on the actual WebAuthn server
	rp := virtualwebauthn.RelyingParty{Name: webauthnConfig.RPName, ID: webauthnConfig.RPID, Origin: WebauthnOrigin}

	// A mock authenticator that represents a security key or biometrics module
	authenticator := virtualwebauthn.NewAuthenticator()

	// Start an attestation request with the relying party to register a new webauthn authenticator.
	// In this test we run an instance of fxamacker/webauthn locally, but we could just as well get
	// this from an an actual server.
	attestation := startWebauthnRegister(challenge, username)

	// Parses the attestation options we got from the relying party to ensure they're valid
	attestationOptions := createAttestationOptions(attestation)

	// Creates an attestation response that we can send to the relying party as if it came from
	// an actual browser and authenticator.
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attestationOptions)

	// Finish the register operation by sending the attestation response. An actual relying party
	// would keep all the data related to the user, but in this test we need to hold onto the
	// credential object for later usage.
	verifyWebauthnRegister(attestation, attestationResponse)

	// Add the userID to the mock authenticator so it can return it in assertion responses.
	authenticator.Options.UserHandle = []byte(attestationOptions.UserID)

	// Add the EC2 credential to the mock authenticator
	authenticator.AddCredential(cred)

	return attestationOptions, attestationResponse
}

func createAttestationOptions(attestation *WebauthnAttestation) *virtualwebauthn.AttestationOptions {
	// Parses the attestation options we got from the relying party to ensure they're valid
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(attestation.Options)
	if err != nil {
		panic(fmt.Sprintf("Error generation attestation options: %v", err))
	}

	return attestationOptions
}

// starts a webauthn registration by creating a new user and generating an attestation challenge
func startWebauthnRegister(challenge string, username string) *WebauthnAttestation {
	// Create a new user for the webauthn registration
	user := newWebauthnUser(username)

	// If a challenge flag was provided, set its length in the config
	if len(challenge) > 0 {
		webauthnConfig.ChallengeLength = len(challenge)
	}

	// Generate the attestation options
	options, _ := webauthn.NewAttestationOptions(&webauthnConfig, user)

	// If a challenge flag was provided, set it in the options
	if len(challenge) > 0 {
		options.Challenge = []byte(challenge)
	}

	// Marshal the options to JSON for storage
	optionsJSON, _ := json.Marshal(options)
	return &WebauthnAttestation{User: user, Challenge: options.Challenge, Options: string(optionsJSON)}
}

// simulates the final step of a webauthn registration by verifying the attestation to ensure it's valid
func verifyWebauthnRegister(attestation *WebauthnAttestation, response string) *webauthn.Credential {
	// Parse the attestation response
	parsedAttestation, _ := webauthn.ParseAttestation(strings.NewReader(response))

	// Verify the attestation to ensure it's valid
	_, _, _ = webauthn.VerifyAttestation(parsedAttestation, &webauthn.AttestationExpectedData{
		Origin:           WebauthnOrigin,
		RPID:             WebauthnDomain,
		CredentialAlgs:   []int{webauthn.COSEAlgES256, webauthn.COSEAlgRS256},
		Challenge:        base64.RawURLEncoding.EncodeToString(attestation.Challenge),
		UserVerification: webauthn.UserVerificationPreferred,
	})

	return parsedAttestation.AuthnData.Credential
}

// creates a new webauthn.User object with automated test user's data
func newWebauthnUser(username string) *webauthn.User {
	// Get the current time in an european human-readable format
	currentTime := time.Now().Format("02/01/2006 15:04:05")

	// If a username was provided, use it, otherwise use the default values
	if len(username) > 0 {
		user := &webauthn.User{
			ID:          []byte(generateUserID()),
			Name:        username,
			DisplayName: fmt.Sprintf("%s -- %s", username, currentTime),
		}

		return user
	} else {
		user := &webauthn.User{
			ID:          []byte(DefaultUserID),
			Name:        DefaultUserName,
			DisplayName: fmt.Sprintf("%s -- %s", DefaultUserName, currentTime),
		}

		return user
	}

}

// marshals a struct to JSON either in pretty or compact format
func MarshalJSON(value any, pretty string) []byte {
	// If the pretty flag is set, pretty print the JSON
	if len(pretty) > 0 {
		valueJSON, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			panic(fmt.Sprintf("Error marshalling attestation options: %v", err))
		}
		return valueJSON
	}

	// Otherwise, compact print the JSON
	valueJSON, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("Error marshalling attestation options: %v", err))
	}
	return valueJSON
}

func main() {
	// Parse command line arguments
	challenge := flag.String("challenge", "", "An optional argument to set a specific challenge")
	username := flag.String("username", "", "An optional argument to set a specific username")
	pretty := flag.String("pretty", "", "An optional argument to pretty print the JSON output")
	flag.Parse()

	// Run a webauthn attestation flow
	attestationOptions, attestationResponse := register(*challenge, *username)

	// Unmarshal the webauthn response to get the attestation object and clientDataJSON
	var WebauthnResponse WebauthnResponse
	json.Unmarshal([]byte(attestationResponse), &WebauthnResponse)

	// Decode the clientDataJSON from Base64
	decodedClientDataBytes, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Response.ClientDataJSON)
	if err != nil {
		panic(err)
	}
	// Now unmarshal the JSON bytes into the struct
	var clientData FullClientData
	err = json.Unmarshal(decodedClientDataBytes, &clientData)
	if err != nil {
		panic(err)
	}
	// override the challenge to be a hex string
	clientData.Challenge = encodeToHex([]byte(clientData.Challenge))

	// Decode the attestationObject from Base64
	decodedAttestationObjectBytes, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Response.AttestationObject)
	if err != nil {
		panic(err)
	}

	// The data structure to decode into
	var result attestationObject
	cbor.Unmarshal(decodedAttestationObjectBytes, &result)
	if err != nil {
		panic(err)
	}

	// Decode the WebauthnResponse.Id from Base64
	WebauthnResponseIdByte, err := base64.RawURLEncoding.DecodeString(WebauthnResponse.Id)
	if err != nil {
		log.Fatalf("error decoding base64 string: %v", err)
	}

	// Create the WebAuthnRegister struct to hold all the data
	webauthnRegister := WebAuthnRegister{
		User{
			ID:          attestationOptions.UserID,
			Name:        attestationOptions.UserName,
			DisplayName: attestationOptions.UserDisplayName,
		},
		webauthnConfig,
		attestationOptions,
		WebauthnResponseComplete{
			Id:    encodeToHex(WebauthnResponseIdByte),
			RawId: WebauthnResponse.RawId,
			AttestationObject: FullAttestationObject{
				Format: result.Format,
				Statement: attestationStatementClean{
					Algorithm: result.Statement.Algorithm,
					Signature: encodeToHex(result.Statement.Signature),
				},
				AuthData: encodeToHex(result.AuthData),
			},
			ClientDataJSON: clientData,
		},
		WebAuthnResponseRaw{
			AttestationObject: encodeToHex(decodedAttestationObjectBytes),
			ClientDataJSON:    encodeToHex(decodedClientDataBytes),
		},
	}

	// Output the data in JSON format
	webAuthnRegisterDataJSON := MarshalJSON(webauthnRegister, *pretty)
	fmt.Print(string(webAuthnRegisterDataJSON))

}

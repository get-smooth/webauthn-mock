package main

import (
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
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
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
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
	Id       string `json:"id"`
	RawId    string `json:"rawId"`
	Response struct {
		AttestationObject string `json:"attestationObject"`
		ClientDataJSON    string `json:"clientDataJSON"`
	}
}

type ECDSASignature struct {
	R, S *big.Int
}

type attestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}
type attestationStatementClean struct {
	Algorithm int    `json:"alg"`
	Signature string `json:"sig"`
	R         string `json:"r"`
	S         string `json:"s"`
}
type attestationObject struct {
	Format    string               `json:"fmt"`
	Statement attestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type FullAttestationObject struct {
	Raw64     string                    `json:"raw64"`
	Format    string                    `json:"fmt"`
	Statement attestationStatementClean `json:"attStmt"`
	AuthData  AuthDataDecoded           `json:"authData"`
}

type WebauthnResponseComplete struct {
	Id                string `json:"id"`
	RawId             string `json:"rawId"`
	AttestationObject FullAttestationObject
	ClientDataJSON    FullClientData
}

type WebAuthnResponseRaw struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthData          string `json:"authData"`
}

type WebAuthnRegister struct {
	WebauthnUser             User                                `json:"user"`
	WebauthnConfig           webauthn.Config                     `json:"config"`
	WebauthnOptions          *virtualwebauthn.AttestationOptions `json:"options"`
	WebauthnResponseComplete WebauthnResponseComplete            `json:"responseDecoded"`
	WebAuthnResponseRaw      WebAuthnResponseRaw                 `json:"response"`
}

type AuthDataDecoded struct {
	RpIdHash            string `json:"rpIdHash"`
	Flags               string `json:"flags"`
	SignCount           string `json:"signCount"`
	Aaguid              string `json:"aaguid"`
	CredentialIdLength  uint16 `json:"credentialIdLength"`
	CredentialId        string `json:"credentialId"`
	CredentialPublicKey string `json:"credentialPublicKey"`
	PubKeyX             string `json:"pubKeyX"`
	PubKeyY             string `json:"pubKeyY"`
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

func decodeAuthData(authData []byte) AuthDataDecoded {
	// Ensure authData is at least 37 bytes
	if len(authData) < 37 {
		panic("authData is too short")
	}

	// Parse rpIdHash
	rpIdHash := authData[:32]

	// Parse flags
	flags := authData[32]

	// Parse signCount
	signCount := authData[33:37]

	// Offset where attestedCredentialData starts
	offset := 37

	// AAGUID is the next 16 bytes
	aaguid := authData[offset : offset+16]
	offset += 16

	// credentialIdLength is the next 2 bytes
	credentialIdLength := binary.BigEndian.Uint16(authData[offset : offset+2])
	offset += 2

	// credentialId is the next credentialIdLength bytes
	credentialId := authData[offset : offset+int(credentialIdLength)]
	offset += int(credentialIdLength)

	// The remaining bytes are for credentialPublicKey which is COSE-encoded.
	// Its parsing is more involved and depends on your needs.
	credentialPublicKey := authData[offset:]

	// Decode the credentialPublicKey
	var coseMap map[int]interface{}
	if err := cbor.Unmarshal(credentialPublicKey, &coseMap); err != nil {
		panic(err)
	}

	// Extract the x and y coordinates of the public key and convert them to big.Int
	xBytes := coseMap[-2].([]byte)
	yBytes := coseMap[-3].([]byte)
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return AuthDataDecoded{
		RpIdHash:            encodeToHex(rpIdHash),
		Flags:               fmt.Sprintf("%08b", flags),
		SignCount:           encodeToHex(signCount),
		Aaguid:              encodeToHex(aaguid),
		CredentialIdLength:  credentialIdLength,
		CredentialId:        encodeToHex(credentialId),
		CredentialPublicKey: encodeToHex(credentialPublicKey),
		PubKeyX:             "0x" + x.Text(16),
		PubKeyY:             "0x" + y.Text(16),
	}
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

	// Decode the Base64URL string to bytes then encode to hex
	decodedBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		fmt.Println("Error decoding base64URL:", err)
		return
	}
	clientData.Challenge = encodeToHex(decodedBytes)

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

	// Decode the authData
	decodedAuthData := decodeAuthData(result.AuthData)

	// Extract r and s from the DER-encoded signature
	var sig ECDSASignature
	asn1.Unmarshal(result.Statement.Signature, &sig)

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
					R:         "0x" + sig.R.Text(16),
					S:         "0x" + sig.S.Text(16),
				},
				AuthData: decodedAuthData,
			},
			ClientDataJSON: clientData,
		},
		WebAuthnResponseRaw{
			AttestationObject: encodeToHex(decodedAttestationObjectBytes),
			ClientDataJSON:    encodeToHex(decodedClientDataBytes),
			AuthData:          encodeToHex(result.AuthData),
		},
	}

	// Output the data in JSON format
	webAuthnRegisterDataJSON := MarshalJSON(webauthnRegister, *pretty)
	fmt.Print(string(webAuthnRegisterDataJSON))
}

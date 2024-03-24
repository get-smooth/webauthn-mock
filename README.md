# Webauthn Mock

This repository contains a mock implementation of the WebAuthn API designed for testing and development purposes. It simulates the WebAuthn authentication process, providing developers with a tool to integrate and test WebAuthn functionalities without the need to deal with a browser and an authenticator.

Please note, that implementation is not intended for use in production environments. Also, it is an opinionated implementation and may not cover all the edge cases and scenarios that a real WebAuthn implementation would. This implementation is intended to mock our current needs when dealing with p256r1 elliptic curve and ES256 algorithm for passkey creation.

## Installation

To use this mock WebAuthn library, you need to have Go version 1.11 or later installed on your machine. If you don't have Go installed, you can install it using Homebrew or consult the official Go download page for detailed installation instructions and alternative methods.

```bash
brew install go
```

> For users on platforms without Homebrew or preferring other methods, please refer to the comprehensive guides available on the official [official Go installation guide](https://go.dev/dl/).

## Usage

The mock WebAuthn implementation supports simulating both the attestation and assertion flows to facilitate the testing of WebAuthn integration in your projects.

### Simulating the Attestation Flow

The attestation flow involves generating options for creating a new credential, creating the credential, and then verifying it. This mock library automates these steps to simplify the development and testing of the WebAuthn registration process and return all the information generated/used during the process.

To execute the basic attestation flow, use the following command:

```bash
bash run.sh
```

You can customize the attestation process by providing a specific challenge and/or username as follows:

```bash
bash run.sh --challenge <custom-challenge> --username <custom-username> --pretty true
```

#### Details

Here are some information about the first-level keys in the output:

- `user`: Contains the user information, including the user ID, name, and display name. This data is included in the options when creating a new credential.
- `config`: Contains the configuration used for the attestation process, such as the challenge length, timeout, RPID, RP name, authenticator attachment, resident key, user verification, attestation, and credential algorithms.
- `options`: Contains the options generated for creating a new credential, including the challenge, RPID, RP name, user ID, username, and user display name. This is the options object that should be passed to the WebAuthn API when creating a new credential.
- `responseDecoded`: Contains the decoded response from the authenticator, including the attestation object, client data JSON, and the fully decoded auth data. This data is used to verify the credential and is included in the response object.
- `response`: Contains the raw response from the authenticator, including the attestation object, client data JSON, and the raw auth data. This data is formatted as a hex string and is included in the response object.

#### Example Output

```sh
bash scripts/run.sh --challenge 1711126985 --username qdqd.smoo.th --pretty true
```

```json
{
  "user": {
    "id": "SVHZltDBSZebeyn1V-Pn7A",
    "name": "qdqd.smoo.th",
    "displayName": "qdqd.smoo.th -- 24/03/2024 19:49:05"
  },
  "config": {
    "ChallengeLength": 10,
    "Timeout": 60000,
    "RPID": "smoo.th",
    "RPName": "Smooth Keys",
    "RPIcon": "",
    "AuthenticatorAttachment": "platform",
    "ResidentKey": "",
    "UserVerification": "required",
    "Attestation": "none",
    "CredentialAlgs": [-7]
  },
  "options": {
    "challenge": "MTcxMTEyNjk4NQ==",
    "rpId": "smoo.th",
    "rpName": "Smooth Keys",
    "user": "SVHZltDBSZebeyn1V-Pn7A",
    "userName": "qdqd.smoo.th",
    "userDisplayName": "qdqd.smoo.th -- 24/03/2024 19:49:05"
  },
  "responseDecoded": {
    "id": "0x7b25c4f4f37bf773acd525a318f370b728bbf019aef9b1db71d9a11d551f5cb4",
    "rawId": "eyXE9PN793Os1SWjGPNwtyi78Bmu-bHbcdmhHVUfXLQ",
    "AttestationObject": {
      "raw64": "",
      "fmt": "packed",
      "attStmt": {
        "alg": -7,
        "sig": "0x30450220470ef6cab72c76c90c2ed5b74083308537131016cf613512b083a96c2779b26102210089eb3f9396d8912226fee7f1675570c28969421a552b8ed9f433cc71c8c014a7",
        "r": "0x470ef6cab72c76c90c2ed5b74083308537131016cf613512b083a96c2779b261",
        "s": "0x89eb3f9396d8912226fee7f1675570c28969421a552b8ed9f433cc71c8c014a7"
      },
      "authData": {
        "rpIdHash": "0x8d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b2",
        "flags": "01000101",
        "signCount": "0x00000000",
        "aaguid": "0x8af783840123be8fd93769912f48360a",
        "credentialIdLength": 32,
        "credentialId": "0x7b25c4f4f37bf773acd525a318f370b728bbf019aef9b1db71d9a11d551f5cb4",
        "credentialPublicKey": "0xa50102032620012158207e00adf2f1d98330aa927c4ee30be6167c958b194f5cbb6aa46b08ae30bc1e712258202ee151b687caa8f5c4053539edcbb3f45f67d5818101f5fff43ae352dbadac0f",
        "pubKeyX": "0x7e00adf2f1d98330aa927c4ee30be6167c958b194f5cbb6aa46b08ae30bc1e71",
        "pubKeyY": "0x2ee151b687caa8f5c4053539edcbb3f45f67d5818101f5fff43ae352dbadac0f"
      }
    },
    "ClientDataJSON": {
      "type": "webauthn.create",
      "challenge": "0x4d5463784d5445794e6a6b344e51",
      "origin": "https://smoo.th"
    }
  },
  "response": {
    "attestationObject": "0xa363666d74667061636b65646761747453746d74a263616c672663736967584730450220470ef6cab72c76c90c2ed5b74083308537131016cf613512b083a96c2779b26102210089eb3f9396d8912226fee7f1675570c28969421a552b8ed9f433cc71c8c014a768617574684461746158a48d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b245000000008af783840123be8fd93769912f48360a00207b25c4f4f37bf773acd525a318f370b728bbf019aef9b1db71d9a11d551f5cb4a50102032620012158207e00adf2f1d98330aa927c4ee30be6167c958b194f5cbb6aa46b08ae30bc1e712258202ee151b687caa8f5c4053539edcbb3f45f67d5818101f5fff43ae352dbadac0f",
    "clientDataJSON": "0x7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224d5463784d5445794e6a6b344e51222c226f726967696e223a2268747470733a2f2f736d6f6f2e7468227d",
    "authData": "0x8d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b245000000008af783840123be8fd93769912f48360a00207b25c4f4f37bf773acd525a318f370b728bbf019aef9b1db71d9a11d551f5cb4a50102032620012158207e00adf2f1d98330aa927c4ee30be6167c958b194f5cbb6aa46b08ae30bc1e712258202ee151b687caa8f5c4053539edcbb3f45f67d5818101f5fff43ae352dbadac0f"
  }
}
```

### Assertion flow

As of the current version, the assertion flow simulation is not yet implemented. This functionality is essential for testing the login process with WebAuthn and will be added in future updates.

## Build

To build the mock WebAuthn library, you can use the following script:

```bash
bash build.sh
```

The script will compile the Go code and generate a binary file named `register` in the `bin` directory. The generated file is a binary executable specific to your operating system and architecture.

## License

This mock WebAuthn library is open-source and available under the [MIT License](./LICENSE). Feel free to use, modify, and distribute it according to the license terms.

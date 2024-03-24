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
    "id": "X9TI3KgNTy2-7jg0Gt4biA",
    "name": "qdqd.smoo.th",
    "displayName": "qdqd.smoo.th -- 24/03/2024 19:59:48"
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
    "user": "X9TI3KgNTy2-7jg0Gt4biA",
    "userName": "qdqd.smoo.th",
    "userDisplayName": "qdqd.smoo.th -- 24/03/2024 19:59:48"
  },
  "responseDecoded": {
    "id": "0x0a3b24861fe1044e693ace74b4055b1bab83ece919e17b13fd80256e4d758d5e",
    "rawId": "Cjskhh_hBE5pOs50tAVbG6uD7OkZ4XsT_YAlbk11jV4",
    "AttestationObject": {
      "raw64": "",
      "fmt": "packed",
      "attStmt": {
        "alg": -7,
        "sig": "0x3045022100ed74a1a8a1357b3716e44ac4b794a364821098843f28721886e270e8e264eb1c02201ebbe05b440f21294c89b5454f1b99d0207fe6944dac634237ad9dd67c47765d",
        "r": "0xed74a1a8a1357b3716e44ac4b794a364821098843f28721886e270e8e264eb1c",
        "s": "0x1ebbe05b440f21294c89b5454f1b99d0207fe6944dac634237ad9dd67c47765d"
      },
      "authData": {
        "rpIdHash": "0x8d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b2",
        "flags": "01000101",
        "signCount": "0x00000000",
        "aaguid": "0x1fd0bdfd1955a44c7899bb02ea76a9db",
        "credentialIdLength": 32,
        "credentialId": "0x0a3b24861fe1044e693ace74b4055b1bab83ece919e17b13fd80256e4d758d5e",
        "credentialPublicKey": "0xa5010203262001215820928ddaee82830b1dddc2b3f1c5ff0c447b8f5513788a423a07a07c3da534f64c2258205118e06ce456daa6f3b0f811b3d2d6321f944c8f81f0313b96ff7475d85f59af",
        "pubKeyX": "0x928ddaee82830b1dddc2b3f1c5ff0c447b8f5513788a423a07a07c3da534f64c",
        "pubKeyY": "0x5118e06ce456daa6f3b0f811b3d2d6321f944c8f81f0313b96ff7475d85f59af"
      }
    },
    "ClientDataJSON": {
      "type": "webauthn.create",
      "challenge": "0x31373131313236393835",
      "origin": "https://smoo.th"
    }
  },
  "response": {
    "attestationObject": "0xa363666d74667061636b65646761747453746d74a263616c67266373696758473045022100ed74a1a8a1357b3716e44ac4b794a364821098843f28721886e270e8e264eb1c02201ebbe05b440f21294c89b5454f1b99d0207fe6944dac634237ad9dd67c47765d68617574684461746158a48d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b245000000001fd0bdfd1955a44c7899bb02ea76a9db00200a3b24861fe1044e693ace74b4055b1bab83ece919e17b13fd80256e4d758d5ea5010203262001215820928ddaee82830b1dddc2b3f1c5ff0c447b8f5513788a423a07a07c3da534f64c2258205118e06ce456daa6f3b0f811b3d2d6321f944c8f81f0313b96ff7475d85f59af",
    "clientDataJSON": "0x7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224d5463784d5445794e6a6b344e51222c226f726967696e223a2268747470733a2f2f736d6f6f2e7468227d",
    "authData": "0x8d39d641f9950ae5e0c14e7b76a61878abeeda4ac38c4b94313025fc065501b245000000001fd0bdfd1955a44c7899bb02ea76a9db00200a3b24861fe1044e693ace74b4055b1bab83ece919e17b13fd80256e4d758d5ea5010203262001215820928ddaee82830b1dddc2b3f1c5ff0c447b8f5513788a423a07a07c3da534f64c2258205118e06ce456daa6f3b0f811b3d2d6321f944c8f81f0313b96ff7475d85f59af"
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

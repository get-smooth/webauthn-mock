# Webauthn Mock

This repository contains a mock implementation of the WebAuthn API designed for testing and development purposes. It simulates the WebAuthn authentication process, providing developers with a tool to integrate and test WebAuthn functionalities without the need to deal with a browser and an authenticator. Please note, that implementation is not intended for use in production environments.

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
bash run.sh --challenge <custom-challenge> --username <custom-username>
```

#### Example Output

```sh
bash run.sh --challenge 1711126985 --username qdqd.smoo.th
```

```json
{
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
  "response": {
    "type": "public-key",
    "id": "Vy2ia7TYsjLjNW0m5L3uLF5tYFJecchJlFeUQ1oRTHU",
    "rawId": "Vy2ia7TYsjLjNW0m5L3uLF5tYFJecchJlFeUQ1oRTHU",
    "response": {
      "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgZvVpxxl7d_f3xJv2a4sE9Fqd0iE6wZfbhhnoUWlAEQ8CIQD0L0feBi8tR2_epZZyY_2_aFkBVtmeI_Fq-av6Xk4QzGhhdXRoRGF0YVikjTnWQfmVCuXgwU57dqYYeKvu2krDjEuUMTAl_AZVAbJFAAAAAJE-Bq0edy2ubxlh8cxAQsIAIFctomu02LIy4zVtJuS97ixebWBSXnHISZRXlENaEUx1pQECAyYgASFYIOCwuhlCju1Efhr0YnEBvkM8khY3_hrFuOkn4b-R9hXqIlggCOszFac0ubjRPcHRjLVO55Wrv32HxoEi1bHyLrZQdoQ",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTVRjeE1URXlOams0TlEiLCJvcmlnaW4iOiJodHRwczovL3Ntb28udGgifQ"
    }
  },
  "user": {
    "id": "-30Mot6kTCySOd85FJ6pow",
    "name": "qdqd.smoo.th",
    "displayName": "qdqd.smoo.th -- 22/03/2024 18:03:16"
  },
  "options": {
    "rpId": "smoo.th",
    "rpName": "Smooth Keys",
    "user": "-30Mot6kTCySOd85FJ6pow",
    "userName": "qdqd.smoo.th",
    "userDisplayName": "qdqd.smoo.th -- 22/03/2024 18:03:16",
    "challenge": "MTcxMTEyNjk4NQ"
  }
}
```

### Assertion flow

As of the current version, the assertion flow simulation is not yet implemented. This functionality is essential for testing the login process with WebAuthn and will be added in future updates.

## License

This mock WebAuthn library is open-source and available under the [MIT License](./LICENSE). Feel free to use, modify, and distribute it according to the license terms.

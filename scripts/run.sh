#!/bin/bash

# call the attestation flow
go run cmd/webauthn-mock/utils.go cmd/webauthn-mock/register.go "$@"

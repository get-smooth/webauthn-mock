#!/bin/bash

# build the attestation flow
go build -o bin/register cmd/webauthn-mock/register.go cmd/webauthn-mock/utils.go

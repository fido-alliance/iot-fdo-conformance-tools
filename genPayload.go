package main

import (
	"log"

	"github.com/WebauthnWorks/fdo-rv/fdoshared"
)

func GenPayload22() {
	log.Println("Generating OwnerSign22....")

	var ownerSign fdoshared.OwnerSign22
	log.Println(ownerSign)
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/freetocompute/kebe/pkg/auth"
	"github.com/freetocompute/kebe/pkg/dashboard/requests"
	loginRequests "github.com/freetocompute/kebe/pkg/login/requests"
	"gopkg.in/macaroon.v2"
	"strings"
)

const (
	Secret1 = "some_shared_secret_1"

	// DischargeSecret1 This needs to be shared between the services
	DischargeSecret1 = "some_other_shared_secret_1"
	RootMacaroonLocation = "a location"
	ThirdPartyCaveatId = "is-authorized-or-whatever"
	RootMacaroonId = "some id"
	ThirdPartyURL = "http://example.com"
)

type Server struct {
}

type ThirdPartyServer struct {
}

func main() {
	// The main thread of execution represents the "client"
	var server Server
	var thirdPartyServer ThirdPartyServer

	// It will ask the server for a macaroon based on its payload
	// In this case it will be an ACL object
	aclRequest := requests.ACLRequest{
		Permissions: []string{ "permission-1", "permission-2" },
	}

	serializedRootMacaroon := server.GetRootMacaroonSerialized(&aclRequest)

	// This serialized macaroon would normally be stuck in a response object and sent back to
	// the client. We just deal directly with the serialized macaroon here since the REST layer
	// is separate and not relevant for the test

	// The client (this code) would then need to find out if there is a third party caveat that
	// needs discharging

	// So let's deserialize our macaroon
	rootMacaroon, _ := auth.MacaroonDeserialize(serializedRootMacaroon)

	foundCaveat := false
	for _, cav := range rootMacaroon.Caveats() {
		if cav.Location == ThirdPartyURL {
			foundCaveat = true
			break
		}
	}

	if !foundCaveat {
		// If we didn't find the caveat we expected then we don't know what to do!
		panic(errors.New("expected caveat not found"))
	}

	// Now we need to ask the third-party at that location to discharge this caveat for us,
	// We do this by asking it to verify the user credentials we are going to pass it, so
	// it must reconstruct the root macaroon based on shared secrets
	dischargeRequest := &loginRequests.Discharge{
		Email:    "me@nope.com",
		Password: "definitely_not_my_password",
		CaveatId: ThirdPartyCaveatId,
	}

	unbound := thirdPartyServer.DischargeCaveat(dischargeRequest)

	unbound.Bind(rootMacaroon.Signature())

	// Now that we've got this root macaroon and discharged macaroon we want to use it
	server.RegisterSnapName("my-snap-name", rootMacaroon, unbound)
}

func (s *Server) RegisterSnapName(someSnapName string, rootMacaroon *macaroon.Macaroon, dischargeMacaroon *macaroon.Macaroon) {
	// We are being asked to do something by someone we don't trust.
	// Can we trust them though?
	err := rootMacaroon.Verify([]byte(Secret1), func(caveat string) error {
		return nil
	}, []*macaroon.Macaroon{dischargeMacaroon})

	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(errors.New("something bad happened"))
	} else {
		isAuthorized := false
		for _, cav := range rootMacaroon.Caveats() {
			if string(cav.Id) != ThirdPartyCaveatId {
				isAuthorized = true
				break
			}
		}

		if isAuthorized {
			var email string
			for _, cav := range dischargeMacaroon.Caveats() {
				cavAsString := string(cav.Id)
				if strings.Contains(cavAsString, "email") {
					parts := strings.Split(cavAsString, "=")
					if len(parts) != 2 {
						panic(errors.New("we expect more for our macaroons"))
					}
					email = parts[1]

					fmt.Printf("This is the email of the authenticated user: %s\n", email)
				}
			}
		}
	}
}

func (t *ThirdPartyServer) DischargeCaveat(dischargeRequest *loginRequests.Discharge) *macaroon.Macaroon {
	dischargeRootKey := []byte(DischargeSecret1)

	// We would need to discharge each individual caveat separately if there were more then 1 Third-party caveats,
	// but that's the responsibility of the client to deal with, either through multiple requests or requests with
	// other services
	dm := MustNew(dischargeRootKey, []byte(dischargeRequest.CaveatId), "remote location", macaroon.LatestVersion)

	// We're going to store the email address of the authenticated user as a caveat for the requesting
	// service to use for identification
	_ = dm.AddFirstPartyCaveat([]byte("email=" + dischargeRequest.Email))

	// I believe "normally" this macaroon would be bound like below but Snapcraft expects an "unbound" macaroon
	// dm.Bind(m.Signature())

	// Give the discharged macaroon back to the client
	return dm
}

func GetRootMacaroon(aclRequest *requests.ACLRequest) *macaroon.Macaroon {
	rootKey := Secret1
	m := MustNew([]byte(rootKey), []byte(RootMacaroonId), RootMacaroonLocation, macaroon.V1)

	dischargeRootKey := []byte(DischargeSecret1)
	err := m.AddThirdPartyCaveat(dischargeRootKey, []byte(ThirdPartyCaveatId), ThirdPartyURL)
	if err != nil {
		panic(err)
	}

	bytes, _ := json.Marshal(aclRequest)
	_ = m.AddFirstPartyCaveat(bytes)
	return m
}

func (s *Server) GetRootMacaroonSerialized(aclRequest *requests.ACLRequest) string {
	rootMacaroon := GetRootMacaroon(aclRequest)
	ser, _ := auth.MacaroonSerialize(rootMacaroon)
	return ser
}

func MustNew(rootKey, id []byte, loc string, vers macaroon.Version) *macaroon.Macaroon {
	m, err := macaroon.New(rootKey, id, loc, vers)
	if err != nil {
		panic(err)
	}
	return m
}

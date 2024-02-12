// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Matter Labs
//
// Gets the rough network time using NTS-KE.
// It queries a number of servers and returns the time from the last server that responds.
// It returns an error if it fails to query enough servers or if the time fluctuates too much.

package vault_auth_tee

import (
	"crypto/tls"
	"fmt"
	"gitlab.com/hacklunch/ntp"
	"gitlab.com/hacklunch/ntske"
	"log"
	"math/rand"
	"time"
)

// Gets the rough network time using NTS-KE.
// It queries a number of servers and returns the time from the last server that responds.
// It returns an error if it fails to query enough servers or if the time fluctuates too much.
func getRoughNtsUnixTime() (time.Time, error) {
	tlsconfig := &tls.Config{}
	servers := []string{
		"time.cloudflare.com",
		"nts.ntp.se",
		"gps.ntp.br",
		"paris.time.system76.com",
		"ntp3.fau.de",
		"ptbtime1.ptb.de",
		"ntppool1.time.nl",
		"nts.netnod.se",
		"time.txryan.com",
		"ntpmon.dcs1.biz",
	}

	// Shuffle the servers to avoid always querying the same servers.
	for i := range servers {
		j := rand.Intn(i + 1)
		servers[i], servers[j] = servers[j], servers[i]
	}

	numToQuery := 3
	queried := 0
	sumOffset := time.Duration(0)
	retTime := time.Unix(0, 0)

	for _, server := range servers {
		ke, err := ntske.Connect(server, tlsconfig, false)
		if err != nil {
			log.Printf("Failed to connect to %v: %v\n", server, err)
			continue
		}

		err = ke.Exchange()
		if err != nil {
			log.Printf("Key exchange failed for %v: %v\n", server, err)
			continue
		}

		if len(ke.Meta.Cookie) == 0 {
			log.Printf("No Cookies from %v: %v\n", server, err)
			continue
		}

		if ke.Meta.Algo != ntske.AES_SIV_CMAC_256 {
			log.Printf("Algorithm mismatch for %v: %v\n", server, err)
			continue
		}

		err = ke.ExportKeys()
		if err != nil {
			log.Printf("Failed to export keys from %v: %v\n", server, err)
			continue
		}

		var opt ntp.QueryOptions
		opt.Port = int(ke.Meta.Port)
		opt.NTS = true
		opt.C2s = ke.Meta.C2sKey
		opt.S2c = ke.Meta.S2cKey
		opt.Cookie = ke.Meta.Cookie[0]
		opt.Debug = false

		resp, err := ntp.QueryWithOptions(ke.Meta.Server, opt)
		if err != nil {
			log.Printf("Failed query NTP for %v: %v\n", server, err)
			continue
		}

		err = resp.Validate()
		if err != nil {
			log.Printf("Failed to validate NTP response for %v: %v\n", server, err)
			continue
		}

		sumOffset += resp.ClockOffset.Abs()

		queried++
		if queried >= numToQuery {
			retTime = resp.Time
			break
		}
	}

	if queried < numToQuery {
		return retTime, fmt.Errorf("failed to query enough servers")
	}

	if sumOffset > time.Minute {
		return retTime, fmt.Errorf("queried time fluctuates too much")
	}

	return retTime, nil
}

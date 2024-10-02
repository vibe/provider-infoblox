/*
Copyright 2021 Upbound Inc.
*/

package clients

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/upjet/pkg/terraform"

	"github.com/vibe/provider-infoblox/apis/v1beta1"
)

const (
	// error messages
	errNoProviderConfig      = "no providerConfigRef provided"
	errGetProviderConfig     = "cannot get referenced ProviderConfig"
	errTrackUsage            = "cannot track ProviderConfig usage"
	errExtractCredentials    = "cannot extract credentials"
	errUnmarshalCredentials  = "cannot unmarshal infoblox credentials as JSON"
	errMissingCredentialData = "missing required credential data"
)

// credentialCache stores cached authentication cookies.
// It maps a unique cache key to the cookie string.
var (
	credentialCache = make(map[string]string)
	cacheMutex      sync.RWMutex
)

// IsAuthCookieExpired determines if the authentication cookie has expired.
func IsAuthCookieExpired(ctime int64, timeout int64) (bool, error) {
	if timeout < 0 {
		return false, fmt.Errorf("timeout cannot be negative")
	}

	creationTime := time.Unix(ctime, 0)
	expirationTime := creationTime.Add(time.Duration(timeout) * time.Second)
	currentTime := time.Now()

	return currentTime.After(expirationTime), nil
}

// ParseAuthCookie parses the authentication cookie value to extract ctime and timeout.
func ParseAuthCookie(cookieValue string) (ctime int64, timeout int64, err error) {
	parts := strings.Split(cookieValue, ",")

	for _, part := range parts {
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			continue // Skip invalid parts
		}
		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		switch key {
		case "ctime":
			ctime, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid ctime value: %v", err)
			}
		case "timeout":
			timeout, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid timeout value: %v", err)
			}
		}
	}

	if ctime == 0 || timeout == 0 {
		return 0, 0, fmt.Errorf("ctime or timeout not found in cookie")
	}

	return ctime, timeout, nil
}

func hash(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func GetAuthCookie(server, username, password string) (*http.Cookie, error) {
	wapiVersion := "v2.9"
	ibapauthEndpoint := fmt.Sprintf("https://%s/wapi/%s/userprofile", server, wapiVersion)

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequest("GET", ibapauthEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.SetBasicAuth(username, password)

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for a successful status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %d %s", resp.StatusCode, resp.Status)
	}

	var authCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "ibapauth" {
			authCookie = cookie
			break
		}
	}

	if authCookie == nil {
		return nil, fmt.Errorf("authentication cookie not found in response")
	}

	return authCookie, nil
}

// GetValidAuthCookie handles caching logic to retrieve a valid authentication cookie.
// It checks the cache, validates expiration, requests a new cookie if necessary, and updates the cache.
func GetValidAuthCookie(configRefName, server, username, password string) (string, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", configRefName, username, hash(password))
	fmt.Printf("Checking credential cache for %s\n", cacheKey)

	var finalCookie string

	// Acquire read lock to check the cache
	cacheMutex.RLock()
	cached, ok := credentialCache[cacheKey]
	cacheMutex.RUnlock()

	if ok {
		// Parse the cached cookie to extract ctime and timeout
		ctime, timeout, err := ParseAuthCookie(cached)
		if err != nil {
			fmt.Printf("Error parsing cached cookie: %v. Will request a new cookie.\n", err)
		} else {
			// Check if the cached cookie is expired
			expired, err := IsAuthCookieExpired(ctime, timeout)
			if err != nil {
				fmt.Printf("Error checking cookie expiration: %v. Will request a new cookie.\n", err)
			} else if !expired {
				// Cached cookie is valid
				fmt.Println("Using cached authentication cookie.")
				finalCookie = cached
			} else {
				fmt.Println("Cached authentication cookie is expired. Requesting a new one.")
			}
		}
	} else {
		fmt.Println("No cached authentication cookie found. Requesting a new one.")
	}

	// If finalCookie is still empty, request a new cookie
	if finalCookie == "" {
		// Request a new authentication cookie
		authCookie, err := GetAuthCookie(server, username, password)
		if err != nil {
			return "", errors.Wrap(err, "failed to get authentication cookie")
		}

		// Serialize the cookie to store in cache
		// Assuming the cookie value contains ctime and timeout as "ctime=...,timeout=..."
		finalCookie = authCookie.Value

		// Store the new cookie in the cache with write lock
		cacheMutex.Lock()
		credentialCache[cacheKey] = finalCookie
		cacheMutex.Unlock()

		fmt.Println("Stored new authentication cookie in cache.")
	}

	return finalCookie, nil
}

// TerraformSetupBuilder builds Terraform a terraform.SetupFn function which
// returns Terraform provider setup configuration
func TerraformSetupBuilder(version, providerSource, providerVersion string) terraform.SetupFn {
	return func(ctx context.Context, client client.Client, mg resource.Managed) (terraform.Setup, error) {
		ps := terraform.Setup{
			Version: version,
			Requirement: terraform.ProviderRequirement{
				Source:  providerSource,
				Version: providerVersion,
			},
		}

		configRef := mg.GetProviderConfigReference()
		if configRef == nil {
			return ps, errors.New(errNoProviderConfig)
		}
		pc := &v1beta1.ProviderConfig{}
		if err := client.Get(ctx, types.NamespacedName{Name: configRef.Name}, pc); err != nil {
			return ps, errors.Wrap(err, errGetProviderConfig)
		}

		t := resource.NewProviderConfigUsageTracker(client, &v1beta1.ProviderConfigUsage{})
		if err := t.Track(ctx, mg); err != nil {
			return ps, errors.Wrap(err, errTrackUsage)
		}

		data, err := resource.CommonCredentialExtractor(ctx, pc.Spec.Credentials.Source, client, pc.Spec.Credentials.CommonCredentialSelectors)
		if err != nil {
			return ps, errors.Wrap(err, errExtractCredentials)
		}
		creds := map[string]string{}
		if err := json.Unmarshal(data, &creds); err != nil {
			return ps, errors.Wrap(err, errUnmarshalCredentials)
		}

		requiredFields := []string{"server", "username", "password"}
		for _, field := range requiredFields {
			if _, exists := creds[field]; !exists {
				return ps, errors.New(errMissingCredentialData + ": " + field)
			}
		}

		server := creds["server"]
		username := creds["username"]
		password := creds["password"]

		finalCookie, err := GetValidAuthCookie(configRef.Name, server, username, password)
		if err != nil {
			return ps, errors.Wrap(err, "unable to obtain a valid authentication cookie")
		}

		ps.Configuration = map[string]any{
			"server":   server,
			"ibapauth": finalCookie,
		}
		return ps, nil
	}
}

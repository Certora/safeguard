package etherapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

var prankCache map[string]string
var tryPrank bool = false
var prankLoaded bool = false

func getOrPrank(url string) (io.Reader, error) {
	if !prankLoaded {
		file, exists := os.LookupEnv("SAFEGUARD_PRANK_URLS")
		if exists {
			data, err := os.ReadFile(file)
			if err == nil {
				err = json.Unmarshal(data, &prankCache)
				if err == nil {
					tryPrank = true
				}
			}
		}
		prankLoaded = true
	}
	if !tryPrank {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("Server responded with status code %s", resp.Status)
		}
		return resp.Body, nil
	}
	contents, exists := prankCache[url]
	if !exists {
		return nil, fmt.Errorf("'Server' didn't have response for %s", url)
	}
	return strings.NewReader(contents), nil
}

func getHost() string {
	p, exists := os.LookupEnv("CERT_HTTP_API_URL")
	if !exists {
		return "http://localhost:5000"
	}
	return p
}

func QueryJsonEndpoint[T any](endPoint string, target *T) error {
	b, err := getOrPrank(fmt.Sprintf("%s/%s", getHost(), endPoint))
	if err != nil {
		return err
	}
	if rc, ok := b.(io.ReadCloser); ok {
		defer rc.Close()
	}
	err = json.NewDecoder(b).Decode(target)
	if err != nil {
		return fmt.Errorf("Failed to parse http respose %s", err)
	}
	return nil
}

var nodeId = os.Getenv("CERT_CLIENT_ID")

func sendUpdateToEndpoint(
	endpointURL string,
	checkResults map[string]interface{},
) error {
	// Create the payload
	payload := make(map[string]interface{})
	for k, v := range checkResults {
		if k == "client_id" {
			return fmt.Errorf("Update already includes client_id %s, cannot tag result", v)
		}
		payload[k] = v
	}
	payload["client_id"] = nodeId
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Post the request
	resp, err := http.Post(endpointURL, "application/x-www-form-urlencoded", strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

func PostUpdate(endPointName string, checkResults map[string]interface{}) error {
	endpoint := fmt.Sprintf("%s/%s", getHost(), endPointName)
	return sendUpdateToEndpoint(
		endpoint, checkResults,
	)
}

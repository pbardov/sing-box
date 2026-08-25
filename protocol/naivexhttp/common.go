package naivexhttp

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultMaxEachPostBytes = 1000000
	defaultMaxBufferedPosts = 30

	headerConnectAuthority = "-connect-authority"
	headerPadding          = "Padding"
	headerXPaddingKey      = "x_padding"
)

func normalizeBasePath(pathValue string) (string, string) {
	pathPart, query, _ := strings.Cut(pathValue, "?")
	if pathPart == "" {
		pathPart = "/"
	}
	if pathPart[0] != '/' {
		pathPart = "/" + pathPart
	}
	if !strings.HasSuffix(pathPart, "/") {
		pathPart += "/"
	}
	return pathPart, query
}

func appendPath(basePath string, value string) string {
	if basePath == "/" {
		return "/" + value
	}
	return basePath + value
}

func newSessionID() (string, error) {
	var sessionID [16]byte
	_, err := rand.Read(sessionID[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sessionID[:]), nil
}

func validSessionID(sessionID string) bool {
	if len(sessionID) < 16 || len(sessionID) > 80 {
		return false
	}
	for _, char := range sessionID {
		if char >= 'a' && char <= 'z' {
			continue
		}
		if char >= 'A' && char <= 'Z' {
			continue
		}
		if char >= '0' && char <= '9' {
			continue
		}
		if char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}

func requestPadding(rawURL string) string {
	padding := generatePaddingHeader()
	referrer, err := url.Parse(rawURL)
	if err != nil {
		return padding
	}
	referrer.RawQuery = headerXPaddingKey + "=" + padding
	return referrer.String()
}

func extractXPadding(request *http.Request) string {
	referrer := request.Header.Get("Referer")
	if referrer != "" {
		referrerURL, err := url.Parse(referrer)
		if err == nil {
			return referrerURL.Query().Get(headerXPaddingKey)
		}
	}
	return request.URL.Query().Get(headerXPaddingKey)
}

func cleanHeader(value string) bool {
	return !strings.ContainsAny(value, "\r\n") && len(value) <= 4096
}

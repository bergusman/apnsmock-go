package mock

import (
	"crypto/ecdsa"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type DeviceToken struct {
	Token        string
	Topic        string
	Unregistered int64
}

type Push struct {
	ID        string
	Headers   http.Header
	Payload   []byte
	Status    int
	Reason    string
	Timestamp int64
}

type TokenPublicKeyFunc func(keyID, teamID string) *ecdsa.PublicKey
type DeviceTokenFunc func(token string) *DeviceToken
type PushFunc func(push *Push)

type Handler struct {
	TokenPublicKey TokenPublicKeyFunc
	DeviceToken    DeviceTokenFunc
	Push           PushFunc
}

func NewHandler(keyFunc TokenPublicKeyFunc, tokenFunc DeviceTokenFunc, pushFunc PushFunc) *Handler {
	return &Handler{
		TokenPublicKey: keyFunc,
		DeviceToken:    tokenFunc,
		Push:           pushFunc,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var id string

	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = v
	}

	var payload []byte

	notOk := func(status int, reason string, stamp int64) {
		h.Push(&Push{
			ID:        id,
			Headers:   headers,
			Payload:   payload,
			Status:    status,
			Reason:    reason,
			Timestamp: stamp,
		})
		w.WriteHeader(status)
		if stamp > 0 {
			fmt.Fprintf(w, `{"reason":"%v","timestamp":%v}`, reason, stamp)
		} else {
			fmt.Fprintf(w, `{"reason":"%v"}`, reason)
		}
	}

	done := func() {
		h.Push(&Push{
			ID:      id,
			Headers: headers,
			Payload: payload,
			Status:  200,
		})
		w.WriteHeader(200)
	}

	// apns-id
	if ids, ok := headers["apns-id"]; ok {
		id = ids[0]
		if _, err := uuid.Parse(id); err != nil {
			id = strings.ToUpper(uuid.NewString())
			w.Header().Set("apns-id", id)
			notOk(400, "BadMessageId", 0)
			return
		} else {
			w.Header().Set("apns-id", id)
		}
		if len(ids) > 1 {
			notOk(400, "DuplicateHeaders", 0)
			return
		}
	} else {
		id = strings.ToUpper(uuid.NewString())
		w.Header().Set("apns-id", id)
	}

	// :method
	if r.Method != http.MethodPost {
		notOk(405, "MethodNotAllowed", 0)
		return
	}

	// :path
	path := r.URL.Path
	if !strings.HasPrefix(path, "/3/device/") {
		notOk(404, "BadPath", 0)
		return
	}

	// Authorization
	auth := r.Header.Get("authorization")
	if len(auth) < 7 {
		notOk(403, "MissingProviderToken", 0)
		return
	}
	if !strings.HasPrefix(strings.ToLower(auth[:7]), "bearer ") {
		notOk(403, "MissingProviderToken", 0)
		return
	}

	// JWT Token
	bearer := strings.TrimSpace(auth[7:])
	token, err := DecodeToken(bearer)
	if err != nil {
		notOk(403, "InvalidProviderToken", 0)
		return
	}
	pub := h.TokenPublicKey(token.KeyID, token.TeamID)
	if pub == nil {
		notOk(403, "InvalidProviderToken", 0)
		return
	}
	if ok, _ := VerifyJWT(bearer, pub); !ok {
		notOk(403, "InvalidProviderToken", 0)
		return
	}
	if token.Expired() {
		notOk(403, "ExpiredProviderToken", 0)
		return
	}

	// apns-expiration
	expirations, ok := headers["apns-expiration"]
	if ok {
		if _, err := strconv.Atoi(expirations[0]); err != nil {
			notOk(400, "BadExpirationDate", 0)
		}
		if len(expirations) > 1 {
			notOk(400, "DuplicateHeaders", 0)
		}
	}

	// apns-priority
	priorities, ok := headers["apns-priority"]
	if ok {
		if _, err := strconv.Atoi(priorities[0]); err != nil {
			notOk(400, "BadPriority", 0)
		}
		if len(priorities) > 1 {
			notOk(400, "DuplicateHeaders", 0)
		}
	}

	// apns-collapse-id
	collapses, ok := headers["apns-collapse-id"]
	if ok {
		collapse := collapses[0]
		if collapse == "" {
			notOk(400, "InvalidCollapseId", 0)
		}
		if len(collapse) > 64 {
			notOk(400, "InvalidCollapseId", 0)
		}
		if len(collapses) > 1 {
			notOk(400, "DuplicateHeaders", 0)
		}
	}

	// apns-push-type
	pushTypes, ok := headers["apns-push-type"]
	if ok {
		ptype := pushTypes[0]
		if ptype != "" && ptype != "alert" && ptype != "background" && ptype != "voip" && ptype != "complication" && ptype != "fileprovider" && ptype != "mdm" {
			notOk(400, "InvalidPushType", 0)
		}
		if len(pushTypes) > 1 {
			notOk(400, "DuplicateHeaders", 0)
		}
	}

	// Device Token
	deviceToken := path[len("/3/device/"):]
	if len(deviceToken) != 64 {
		notOk(400, "BadDeviceToken", 0)
		return
	}

	// Payload
	if r.ContentLength == 0 {
		notOk(400, "PayloadEmpty", 0)
		return
	}

	// apns-topic
	topic := ""
	topics, ok := headers["apns-topic"]
	if ok {
		topic = topics[0]
		if topic == "" {
			notOk(400, "MissingTopic", 0)
			return
		}
		if len(topics) > 1 {
			notOk(400, "DuplicateHeaders", 0)
			return
		}
	} else {
		notOk(400, "MissingTopic", 0)
		return
	}

	// Device Token
	tokenTopic := h.DeviceToken(deviceToken)
	if tokenTopic == nil || tokenTopic.Topic == "" {
		notOk(400, "BadDeviceToken", 0)
		return
	}
	if tokenTopic.Topic != topic {
		notOk(400, "DeviceTokenNotForTopic", 0)
		return
	}
	if tokenTopic.Unregistered > 0 {
		notOk(410, "Unregistered", tokenTopic.Unregistered)
		return
	}

	// Payload size
	if strings.HasSuffix(topic, ".voip") {
		if r.ContentLength > 5120 {
			notOk(413, "PayloadTooLarge", 0)
			return
		}
	} else {
		if r.ContentLength > 4096 {
			notOk(413, "PayloadTooLarge", 0)
			return
		}
	}

	// Body
	defer r.Body.Close()
	payload, err = io.ReadAll(r.Body)
	if err != nil {
		notOk(500, "InternalServerError", 0)
		return
	}

	done()
}

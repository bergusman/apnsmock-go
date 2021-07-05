# APNs Mock Server

Server example:

```Go
key, err := mock.AuthKeyFromFile("AuthKey_XXXXXXXXXX.p8")
if err != nil {
	log.Fatal(err)
}

handler := &mock.Handler{}
handler.TokenPublicKey = func(keyID, teamID string) *ecdsa.PublicKey {
	if keyID == "XXXXXXXXXX" && teamID == "YYYYYYYYYY" {
		return &key.PublicKey
	}
	return nil
}
handler.DeviceToken = func(token string) *mock.DeviceToken {
	if token == "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" {
		return &mock.DeviceToken{
			Token:        token,
			Topic:        "com.example.app",
			Unregistered: 1625475525573,
		}
	}
	return &mock.DeviceToken{
		Token: token,
		Topic: "com.example.app",
	}
}
handler.Push = func(push *mock.Push) {
	fmt.Println(push.Status, push.Reason)
}

http.ListenAndServe(":80", handler)
```

Client example with [apns-go](https://github.com/bergusman/apns-go):

```Go
key, err := apns.AuthKeyFromFile("AuthKey_XXXXXXXXXX.p8")
if err != nil {
	log.Fatal(err)
}

token := apns.NewToken(key, "XXXXXXXXXX", "YYYYYYYYYY")
client := apns.NewClient(token, nil)

n := &apns.Notification{
	DeviceToken: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	Host:        "http://localhost",
	Topic:       "com.example.app",
	Payload: apns.BuildPayload(&apns.APS{
		Alert: "Hi",
	}, nil),
}

fmt.Println(client.Push(n))
```

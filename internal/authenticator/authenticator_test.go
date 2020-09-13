package authenticator

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	snappids "gitlab.snapp.ir/dispatching/snappids/v2"
	"gitlab.snapp.ir/dispatching/soteria/internal/db"
	"gitlab.snapp.ir/dispatching/soteria/internal/topics"
	"gitlab.snapp.ir/dispatching/soteria/pkg/acl"
	"gitlab.snapp.ir/dispatching/soteria/pkg/user"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"testing"
	"time"
)

func TestAuthenticator_Auth(t *testing.T) {
	driverToken, err := getSampleToken(user.Driver,true)
	if err != nil {
		t.Fatal(err)
	}
	passengerToken, err := getSampleToken(user.Passenger, true)
	if err != nil {
		t.Fatal(err)
	}
	invalidToken, err := getSampleToken(user.Passenger, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := getPrivateKey(user.ThirdParty)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := Authenticator{
		PrivateKeys: map[user.Issuer]*rsa.PrivateKey{
			user.ThirdParty: key,
		},
		ModelHandler: MockModelHandler{},
	}
	t.Run("testing driver token auth", func(t *testing.T) {
		ok, err := authenticator.Auth(driverToken)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("testing passenger token auth", func(t *testing.T) {
		ok, err := authenticator.Auth(passengerToken)
		assert.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("testing invalid token auth", func(t *testing.T) {
		ok, err := authenticator.Auth(invalidToken)
		assert.Error(t, err)
		assert.False(t, ok)
	})
}

func TestAuthenticator_Token(t *testing.T) {
	key, err := getPrivateKey(user.ThirdParty)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := getPublicKey(user.ThirdParty)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := Authenticator{
		PrivateKeys: map[user.Issuer]*rsa.PrivateKey{
			user.ThirdParty: key,
		},
		ModelHandler: MockModelHandler{},
	}
	t.Run("testing getting token with valid inputs", func(t *testing.T) {
		tokenString, err := authenticator.Token(acl.ClientCredentials, "snappbox", "KJIikjIKbIYVGj)YihYUGIB&")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return pk, nil
		})
		assert.NoError(t, err)
		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, "snappbox", claims["sub"].(string))
		assert.Equal(t, "100", claims["iss"].(string))
	})
	t.Run("testing getting token with valid inputs", func(t *testing.T) {
		tokenString, err := authenticator.Token(acl.ClientCredentials, "snappbox", "invalid secret")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return pk, nil
		})
		assert.Error(t, err)
		assert.Nil(t, token)
	})
}

func TestAuthenticator_Acl(t *testing.T) {
	key, err := getPrivateKey(user.ThirdParty)
	if err != nil {
		t.Fatal(err)
	}
	tokenString, err := getSampleToken(user.Passenger, true)
	if err != nil {
		t.Fatal(err)
	}
	invalidTokenString, err := getSampleToken(user.Passenger,false)
	if err != nil {
		t.Fatal(t, err)
	}

	hid := &snappids.HashIDSManager{
		Salts: map[snappids.Audience]string{
			snappids.PassengerAudience: "secret",
		},
		Lengths: map[snappids.Audience]int{
			snappids.PassengerAudience: 15,
		},
	}

	authenticator := Authenticator{
		PrivateKeys: map[user.Issuer]*rsa.PrivateKey{
			user.ThirdParty: key,
		},
		AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub},
		ModelHandler:       MockModelHandler{},
		EMQTopicManager:    snappids.NewEMQManager(hid),
		HashIDSManager:     hid,
	}
	t.Run("testing acl with invalid access type", func(t *testing.T) {
		ok, err := authenticator.Acl(acl.PubSub, tokenString, "test")
		assert.Error(t, err)
		assert.False(t, ok)
		assert.Equal(t, "requested access type 3 is invalid", err.Error())
	})
	t.Run("testing acl with invalid token", func(t *testing.T) {
		ok, err := authenticator.Acl(acl.Pub, invalidTokenString, "passenger-event-37de61ff70597cc18d452367ecd9135b")
		assert.False(t, ok)
		assert.Error(t, err)
		assert.Equal(t, "illegal base64 data at input byte 37", err.Error())
	})
	t.Run("testing acl with valid inputs", func(t *testing.T) {
		ok, err := authenticator.Acl(acl.Sub, tokenString, "passenger-event-37de61ff70597cc18d452367ecd9135b")
		assert.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("testing acl with invalid topic", func(t *testing.T) {
		ok, err := authenticator.Acl(acl.Sub, tokenString, "passenger-event-37de61ff70597cc19d452367ecd9135b")
		assert.Error(t, err)
		assert.False(t, ok)
	})
	t.Run("testing acl with invalid access type", func(t *testing.T) {
		ok, err := authenticator.Acl(acl.Pub, tokenString, "passenger-event-37de61ff70597cc18d452367ecd9135b")
		assert.Error(t, err)
		assert.False(t, ok)
	})

}

func TestAuthenticator_ValidateTopicBySender(t *testing.T) {
	hid := &snappids.HashIDSManager{
		Salts: map[snappids.Audience]string{
			snappids.DriverAudience: "secret",
		},
		Lengths: map[snappids.Audience]int{
			snappids.DriverAudience: 15,
		},
	}

	authenticator := Authenticator{
		AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub},
		ModelHandler:       MockModelHandler{},
		EMQTopicManager:    snappids.NewEMQManager(hid),
		HashIDSManager:     hid,
	}

	t.Run("testing valid driver cab event", func(t *testing.T) {
		ok := authenticator.ValidateTopicBySender("driver-event-152384980615c2bd16143cff29038b67", snappids.DriverAudience, 123)
		assert.True(t, ok)
	})

}

func TestAuthenticator_validateAccessType(t *testing.T) {
	type fields struct {
		AllowedAccessTypes []acl.AccessType
	}
	type args struct {
		accessType acl.AccessType
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "#1 testing with no allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{}},
			args:   args{accessType: acl.Sub},
			want:   false,
		},
		{
			name:   "#2 testing with no allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{}},
			args:   args{accessType: acl.Pub},
			want:   false,
		},
		{
			name:   "#3 testing with no allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{}},
			args:   args{accessType: acl.PubSub},
			want:   false,
		},
		{
			name:   "#4 testing with one allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub}},
			args:   args{accessType: acl.Pub},
			want:   true,
		},
		{
			name:   "#5 testing with one allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub}},
			args:   args{accessType: acl.Sub},
			want:   false,
		},
		{
			name:   "#6 testing with two allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub}},
			args:   args{accessType: acl.Sub},
			want:   true,
		},
		{
			name:   "#7 testing with two allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub}},
			args:   args{accessType: acl.Pub},
			want:   true,
		},
		{
			name:   "#8 testing with two allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub}},
			args:   args{accessType: acl.PubSub},
			want:   false,
		},
		{
			name:   "#9 testing with three allowed access type",
			fields: fields{AllowedAccessTypes: []acl.AccessType{acl.Pub, acl.Sub, acl.PubSub}},
			args:   args{accessType: acl.PubSub},
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Authenticator{
				AllowedAccessTypes: tt.fields.AllowedAccessTypes,
			}
			if got := a.validateAccessType(tt.args.accessType); got != tt.want {
				t.Errorf("validateAccessType() = %v, want %v", got, tt.want)
			}
		})
	}
}

type MockModelHandler struct{}

func (rmh MockModelHandler) Save(model db.Model) error {
	return nil
}

func (rmh MockModelHandler) Delete(modelName, pk string) error {
	return nil
}

func (rmh MockModelHandler) Get(modelName, pk string, v interface{}) error {
	key0, _ := getPublicKey(user.Driver)
	key1, _ := getPublicKey(user.Passenger)
	key100, _ := getPublicKey(user.ThirdParty)
	switch pk {
	case "passenger":
		*v.(*user.User) = user.User{
			MetaData:  db.MetaData{},
			Username:  string(user.Passenger),
			Type:      user.EMQUser,
			PublicKey: key1,
			Rules: []user.Rule{
				user.Rule{
					UUID:       uuid.New(),
					Topic:      topics.CabEvent,
					AccessType: acl.Sub,
				},
			},
		}
	case "driver":
		*v.(*user.User) = user.User{
			MetaData:  db.MetaData{},
			Username:  string(user.Driver),
			Type:      user.EMQUser,
			PublicKey: key0,
			Rules: []user.Rule{{
				UUID:       uuid.Nil,
				Endpoint:   "",
				Topic:      topics.DriverLocation,
				AccessType: acl.Pub,
			}, {
				UUID:       uuid.Nil,
				Endpoint:   "",
				Topic:      topics.CabEvent,
				AccessType: acl.Sub,
			}},
		}
	case "snappbox":
		*v.(*user.User) = user.User{
			MetaData:                db.MetaData{},
			Username:                "snappbox",
			Password:                getSamplePassword(),
			Type:                    user.HeraldUser,
			PublicKey:               key100,
			Secret:                  "KJIikjIKbIYVGj)YihYUGIB&",
			TokenExpirationDuration: time.Hour * 72,
		}
	}
	return nil
}

func (rmh MockModelHandler) Update(model db.Model) error {
	return nil
}

func getPublicKey(u user.Issuer) (*rsa.PublicKey, error) {
	var fileName string
	switch u {
	case user.Passenger:
		fileName = "../../test/1.pem"
	case user.Driver:
		fileName = "../../test/0.pem"
	case user.ThirdParty:
		fileName = "../../test/100.pem"
	default:
		return nil, fmt.Errorf("invalid user, public key not found")
	}
	pem, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func getPrivateKey(u user.Issuer) (*rsa.PrivateKey, error) {
	var fileName string
	switch u {
	case user.ThirdParty:
		fileName = "../../test/100.private.pem"
	default:
		return nil, fmt.Errorf("invalid user, private key not found")
	}
	pem, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func getSampleToken(issuer user.Issuer, isValid bool) (string, error) {
	var fileName string
	switch issuer {
	case user.Driver:
		if isValid {
			fileName = "../../test/token.driver.valid.sample"
		}
	case user.Passenger:
		if isValid {
			fileName = "../../test/token.passenger.valid.sample"
		}
	}
	if !isValid {
		fileName = "../../test/token.invalid.sample"
	}
	token, err := ioutil.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	return string(token), nil
}

func getSamplePassword() string {
	hash, _ := bcrypt.GenerateFromPassword([]byte("test"), bcrypt.DefaultCost)
	return string(hash)
}

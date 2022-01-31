package topics

import (
	"crypto/md5" // nolint:gosec
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"gitlab.snapp.ir/dispatching/snappids/v2"
	"gitlab.snapp.ir/dispatching/soteria/v3/pkg/user"
)

const (
	CabEvent          string = "cab_event"
	DriverLocation    string = "driver_location"
	PassengerLocation string = "passenger_location"
	SuperappEvent     string = "superapp_event"
	BoxEvent          string = "box_event"
	SharedLocation    string = "shared_location"
	Chat              string = "chat"
	GeneralCallEntry  string = "general_call_entry"
	NodeCallEntry     string = "node_call_entry"
	CallOutgoing      string = "call_outgoing"
)

const (
	Driver    string = "driver"
	Passenger string = "passenger"
)

// EmqCabHashPrefix is the default prefix for hashing part of cab topic, default value is 'emqch'.
const EmqCabHashPrefix = "emqch"

var ErrDecodeHashID = errors.New("could not decode hash id")

// Topic regular expressions which are used for detecting the topic name.
// topics are prefix with the company name will be trimed before matching
// so they regular expressions should not contain the company prefix.

type Manager struct {
	HashIDSManager *snappids.HashIDSManager
	Company        string
	TopicTemplates []Template
}

// NewTopicManager returns a topic manager to validate topics.
func NewTopicManager(topicList []Topic, hashIDManager *snappids.HashIDSManager, company string) Manager {
	templates := make([]Template, 0)

	for _, topic := range topicList {
		each := Template{
			Type:     topic.Type,
			Template: template.Must(template.New(topic.Type).Parse(topic.Template)),
			HashType: topic.HashType,
			Accesses: topic.Accesses,
		}
		templates = append(templates, each)
	}

	return Manager{
		HashIDSManager: hashIDManager,
		Company:        company,
		TopicTemplates: templates,
	}
}

func (t Manager) ValidateTopicBySender(topic string, issuer user.Issuer, sub string) bool {
	topicTemplate, ok := t.GetTopicTemplate(topic)
	if !ok {
		return false
	}

	fields := make(map[string]string)
	audience := issuerToAudienceStr(issuer)
	fields["audience"] = audience
	fields["company"] = t.Company
	fields["peer"] = peerOfAudience(fields["audience"])

	hashID, err := t.getHashID(topicTemplate.Type, sub, issuer)
	if err != nil {
		return false
	}

	fields["hashId"] = hashID

	if topicTemplate.Type == NodeCallEntry {
		fields["node"] = strings.Split(topic, "/")[4]
	}

	parsedTopic := topicTemplate.Parse(fields)

	return parsedTopic == topic
}

func (t Manager) getHashID(topicType, sub string, issuer user.Issuer) (string, error) {
	if topicType == CabEvent {
		id, err := t.HashIDSManager.DecodeHashID(sub, issuerToAudience(issuer))
		if err != nil {
			return "", ErrDecodeHashID
		}

		hid := md5.Sum([]byte(fmt.Sprintf("%s-%s", EmqCabHashPrefix, strconv.Itoa(id)))) // nolint:gosec

		return fmt.Sprintf("%x", hid), nil
	}

	return sub, nil
}

func (t Manager) GetTopicTemplate(input string) (*Template, bool) {
	topic := strings.TrimPrefix(input, t.Company)

	for _, each := range t.TopicTemplates {
		if each.Regex.MatchString(topic) {
			return &each, true
		}
	}

	return nil, false
}

// IsTopicValid returns true if it finds a topic type for the given topic.
func (t Manager) IsTopicValid(topic string) bool {
	return len(t.GetTopicType(topic)) != 0
}

// GetTopicType finds topic type based on regexes.
func (t Manager) GetTopicType(input string) string {
	topic := strings.TrimPrefix(input, t.Company)

	for _, each := range t.TopicTemplates {
		if each.Regex.MatchString(topic) {
			return each.Type
		}
	}

	return ""
}

// issuerToAudience returns corresponding audience in snappids form.
func issuerToAudience(issuer user.Issuer) snappids.Audience {
	switch issuer {
	case user.Passenger:
		return snappids.PassengerAudience
	case user.Driver:
		return snappids.DriverAudience
	default:
		return -1
	}
}

// issuerToAudienceStr returns corresponding audience in string form.
func issuerToAudienceStr(issuer user.Issuer) string {
	switch issuer {
	case user.Passenger:
		return Passenger
	case user.Driver:
		return Driver
	default:
		return ""
	}
}

func peerOfAudience(audience string) string {
	switch audience {
	case Driver:
		return Passenger
	case Passenger:
		return Driver
	default:
		return ""
	}
}

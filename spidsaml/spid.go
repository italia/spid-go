package spidsaml

import "time"

// Session represents an active SPID session.
type Session struct {
	IDPEntityID  string
	NameID       string
	SessionIndex string
	AssertionXML []byte
	Level        int
	Attributes   map[string]string
}

// Clock is a clock that can be mocked in tests. Thanks to Michael Whatcott
// See https://smartystreets.com/blog/2015/09/go-testing-part-5-testing-with-time/
type Clock struct {
	instant time.Time
}

func (this *Clock) Now() time.Time {
	if this == nil {
		return time.Now()
	}
	return this.instant
}

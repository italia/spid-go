package spidsaml

import "time"

// A clock that can be mocked in tests. Thanks to Michael Whatcott
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

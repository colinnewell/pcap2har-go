package reader

import "time"

type TimeCaptureReader struct {
	times []time.Time
	r     ReaderStream
}

func NewTimeCaptureReader(r ReaderStream) *TimeCaptureReader {
	return &TimeCaptureReader{r: r}
}

func (t *TimeCaptureReader) Read(p []byte) (read int, err error) {
	read, err = t.r.Read(p)
	if err == nil {
		time, err := t.r.Seen()
		if err == nil {
			t.times = append(t.times, time)
		}
	}
	return
}

// Reset clears the list of times.
func (t *TimeCaptureReader) Reset() {
	t.times = []time.Time{}
}

// Seen return the list of times packets were seen.
func (t *TimeCaptureReader) Seen() []time.Time {
	return t.times
}

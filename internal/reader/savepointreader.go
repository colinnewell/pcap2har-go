package reader

import (
	"bytes"
	"io"
)

// SavePointReader is a reader that allows you to save a point in the stream to
// allow you to roll back to it.  This allows you to pass it to a parser, have
// it go down a dead end as you realise it's not that type of data, and roll
// back to that point to try a different parser.
// This is done by storing the data being read, so do Reset the save point once
// you have determined you're going down the correct path.
//
// Note that if this is wrapped within something like a bufio.Reader you may
// need to construct a fresh wrapper to prevent the buffering from adversely
// affecting your results when restoring back to a save point.
type SavePointReader struct {
	r             io.Reader
	alt           bytes.Buffer
	currentReader io.Reader
}

// NewSavePointReader wrap an io.Reader in a SavePointReader and return the new
// SavePointReader.
func NewSavePointReader(r io.Reader) *SavePointReader {
	return &SavePointReader{r: r, currentReader: r}
}

// Read standard io.Reader method.
func (sp *SavePointReader) Read(p []byte) (read int, err error) {
	return sp.currentReader.Read(p)
}

// Reset drops the save point.  You should aim to do this as soon as possible
// as this will make a copy of what's read as long as a save point is in
// actions.
func (sp *SavePointReader) Reset() {
	sp.alt.Reset()
	sp.currentReader = sp.r
}

// SavePoint store the position in the reader so that it can be rolled back to
// this point to be read from again.
func (sp *SavePointReader) SavePoint() {
	sp.Reset()
	sp.setupSavePointReader()
}

func (sp *SavePointReader) setupSavePointReader() {
	sp.currentReader = io.TeeReader(sp.r, &sp.alt)
}

// Restore roll the reader back to the save point.
//
// If you're sure you're not going to need to restore again you can discard the
// save point and avoid continuing to populate the buffer as you continue
// reading onwards.
func (sp *SavePointReader) Restore(discardSavePoint bool) {
	var rdr io.Reader
	if discardSavePoint {
		rdr = sp.r
	} else {
		sp.setupSavePointReader()
		rdr = sp.currentReader
	}
	sp.currentReader = io.MultiReader(bytes.NewBuffer(sp.alt.Bytes()), rdr)
}

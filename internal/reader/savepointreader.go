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
type SavePointReader struct {
	r             io.Reader
	alt           bytes.Buffer
	currentReader io.Reader
}

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
	tee := io.TeeReader(sp.r, &sp.alt)
	sp.currentReader = tee
}

// Restore roll the reader back to the save point
func (sp *SavePointReader) Restore() {
	sp.currentReader = io.MultiReader(&sp.alt, sp.r)
}

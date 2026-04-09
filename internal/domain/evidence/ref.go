package evidence

type ByteOffsetRange struct {
	Start int64
	End   int64
}

func (r ByteOffsetRange) Len() int64 {
	if r.End <= r.Start {
		return 0
	}
	return r.End - r.Start
}

type FindingRef struct {
	Path    string
	Range   ByteOffsetRange
	Hint    string
	Index   int
	Context []byte
}

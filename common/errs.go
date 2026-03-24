package common

type FatalErr struct {
	err error
}

func (e FatalErr) Error() string {
	return e.err.Error()

}
func (e FatalErr) Unwrap() error {
	return e.err
}

func NewFatalError(err error) error {
	return FatalErr{err}
}

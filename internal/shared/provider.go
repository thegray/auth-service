package shared

type Provider string

const (
	ProviderGoogle Provider = "google"
)

func (p Provider) String() string {
	return string(p)
}

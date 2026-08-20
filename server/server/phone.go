package server

func phoneE164Value(phoneE164 *string) string {
	if phoneE164 == nil {
		return ""
	}
	return *phoneE164
}

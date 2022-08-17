package hashcrack_test

import (
	"hashcrack"
	"testing"
)

func TestStringToMd5(t *testing.T) {
	t.Parallel()
	type testCase struct {
		plain string
		want  string
	}

	testCases := []testCase{
		{plain: "hello", want: "5d41402abc4b2a76b9719d911017c592"},
		{plain: "hello, world!", want: "3adbbad1791fbae3ec908894c4963870"},
		{plain: "kE)0yVE'QSP3HZJPMufyQ](z#eQA~}", want: "b58de58bcc309d5e77914f5a735ee3a9"},
	}

	for _, tc := range testCases {
		got := hashcrack.StringToMd5(tc.plain)
		if tc.want != got {
			t.Errorf("StringToMd5(%s): want %s, got %s", tc.plain, tc.want, got)
		}
	}
}

func TestStringToSha256(t *testing.T) {
	t.Parallel()
	type testCase struct {
		plain string
		want  string
	}

	testCases := []testCase{
		{plain: "hello", want: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{plain: "hello, world!", want: "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728"},
		{plain: "kE)0yVE'QSP3HZJPMufyQ](z#eQA~}", want: "ce5e636e9771cbec4628ed9e57f0487046977158f829abd8567e1ad70c3bf40d"},
	}

	for _, tc := range testCases {
		got := hashcrack.StringToSha256(tc.plain)
		if tc.want != got {
			t.Errorf("StringToSha256(%s): want %s, got %s", tc.plain, tc.want, got)
		}
	}
}

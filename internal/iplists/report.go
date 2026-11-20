package iplists

import (
	"fmt"
	"io"
)

// AcceptReport records that a person has reviewed the held update of a provider; the running hub applies it within a minute.
func AcceptReport(dir string, sources map[string]IPSource, provider string, w io.Writer) error {
	if _, ok := sources[provider]; !ok {
		return fmt.Errorf("%q is not a provider in the config", provider)
	}
	st, err := RequestAccept(dir, provider)
	if err != nil {
		return err
	}
	_, removed, added := diffSets(st.CIDRs, st.Pending)
	fmt.Fprintf(w, "provider %s: %s\nthe update replaces %d entries by %d (%d removed, %d added); the hub applies it within a minute\n",
		provider, st.HeldReason, len(st.CIDRs), len(st.Pending), len(removed), len(added))
	for _, r := range removed {
		fmt.Fprintf(w, "- %s\n", r)
	}
	for _, a := range added {
		fmt.Fprintf(w, "+ %s\n", a)
	}
	return nil
}

// diffSets returns what is in b but not a (added) and in a but not b (removed), each in input order.
func diffSets(a, b []string) (same int, removed, added []string) {
	inA, inB := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		inA[x] = true
	}
	for _, x := range b {
		inB[x] = true
	}
	for _, x := range a {
		if inB[x] {
			same++
		} else {
			removed = append(removed, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			added = append(added, x)
		}
	}
	return
}

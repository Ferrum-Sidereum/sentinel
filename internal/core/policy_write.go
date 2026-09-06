package core

import (
	"errors"

	"gopkg.in/yaml.v3"
	"sentinel/internal/policy"
)

func mappingSet(n *yaml.Node, name string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, value)
}

func mappingGet(n *yaml.Node, name string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	return nil
}

// encodeInto encodes v into a node (fresh mapping/scalar structure).
func encodeInto(v any) (*yaml.Node, error) {
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return n, nil
}

// mergeValue merges encoded fresh node into existing dst node, preserving
// comments and unknown keys. Mapping: recurse per key; sequence/scalar: replace
// value but keep dst comments (Head/Line/Foot).
func mergeValue(dst, fresh *yaml.Node) *yaml.Node {
	if dst == nil {
		return fresh
	}
	if dst.Kind == yaml.MappingNode && fresh.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(fresh.Content); i += 2 {
			k := fresh.Content[i].Value
			ex := mappingGet(dst, k)
			if ex == nil {
				dst.Content = append(dst.Content, fresh.Content[i], fresh.Content[i+1])
			} else {
				mappingSet(dst, k, mergeValue(ex, fresh.Content[i+1]))
			}
		}
		return dst
	}
	fresh.HeadComment = dst.HeadComment
	fresh.LineComment = dst.LineComment
	fresh.FootComment = dst.FootComment
	return fresh
}

// UpdatePolicyDocument comment-preserving whole-struct write: every field of
// Policy is merged into the existing document; unknown top-level keys
// (future versions) and comments survive the round-trip.
func UpdatePolicyDocument(raw []byte, p policy.Policy) ([]byte, error) {
	fresh, err := encodeInto(p)
	if err != nil {
		return nil, err
	}
	// Ensure fresh is a mapping node (Encode(Policy) yields DocumentNode).
	freshMap := fresh
	if fresh.Kind == yaml.DocumentNode && len(fresh.Content) == 1 {
		freshMap = fresh.Content[0]
	}
	if len(raw) == 0 {
		return yaml.Marshal(p)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("policy root must be a mapping")
	}
	merged := mergeValue(doc.Content[0], freshMap)
	doc.Content[0] = merged
	return yaml.Marshal(&doc)
}

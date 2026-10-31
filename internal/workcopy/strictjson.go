package workcopy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxJSONDepth bounds the nesting of a settings file or a lockfile.
const maxJSONDepth = 64

// strictJSON decodes one JSON document of the project (composer.json,
// composer.lock, package.json, package-lock.json) the way its strictest
// reader would, so that Michel never accepts a document that composer or
// npm read differently:
//   - an object may not hold two members of the same name, nor two names
//     differing only by case (Go's struct decoding keeps the last one and
//     matches names case-insensitively; PHP and node keep the last one and
//     match exactly);
//   - nothing may follow the document;
//   - nesting is bounded.
//
// Objects are map[string]any with exact keys, arrays []any, numbers
// json.Number, plus string, bool and nil.
func strictJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON document")
	}
	return v, nil
}

// strictObject is strictJSON for a document that must be an object.
func strictObject(raw []byte) (map[string]any, error) {
	v, err := strictJSON(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	return obj, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errors.New("JSON nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil // string, json.Number, bool or nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		folded := map[string]string{}
		for dec.More() {
			ktok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := ktok.(string)
			if !ok {
				return nil, errors.New("unexpected JSON member name")
			}
			if other, dup := folded[strings.ToLower(k)]; dup {
				if other == k {
					return nil, fmt.Errorf("duplicate member %q", k)
				}
				return nil, fmt.Errorf("members %q and %q differ only by case", other, k)
			}
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			folded[strings.ToLower(k)] = k
			obj[k] = v
		}
		if _, err := dec.Token(); err != nil { // the closing brace
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.Token(); err != nil { // the closing bracket
			return nil, err
		}
		return arr, nil
	}
	return nil, errors.New("unexpected JSON delimiter")
}

// exactKeys refuses an object holding a member that differs only by case
// from one of the keys Michel checks ("Config" next to or instead of
// "config"): another reader could take it for the checked one.
func exactKeys(obj map[string]any, keys ...string) error {
	for k := range obj {
		for _, want := range keys {
			if k != want && strings.EqualFold(k, want) {
				return fmt.Errorf("%q differs from %q only by case", k, want)
			}
		}
	}
	return nil
}

// asString returns v when it is a JSON string.
func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asObject returns v when it is a JSON object.
func asObject(v any) (map[string]any, bool) {
	o, ok := v.(map[string]any)
	return o, ok
}

// optString returns the member key of obj as a string: "" when absent, an
// error when present and not a string.
func optString(obj map[string]any, key string) (string, error) {
	v, ok := obj[key]
	if !ok {
		return "", nil
	}
	s, ok := asString(v)
	if !ok {
		return "", fmt.Errorf("%s is not a string", key)
	}
	return s, nil
}

// optBool returns the member key of obj as a bool: false when absent, an
// error when present and not a bool.
func optBool(obj map[string]any, key string) (bool, error) {
	v, ok := obj[key]
	if !ok {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s is not a boolean", key)
	}
	return b, nil
}

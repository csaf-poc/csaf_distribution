// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2022 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2022 Intevation GmbH <https://intevation.de>

package util

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestPathEval_Compile(t *testing.T) {
	pathEval := NewPathEval()
	eval, err := pathEval.Compile("foo")
	if err != nil {
		t.Error(err)
	}

	// Check caching
	eval1, err := pathEval.Compile("foo")
	if err != nil {
		t.Error(err)
	}
	if reflect.ValueOf(eval).Pointer() != reflect.ValueOf(eval1).Pointer() {
		t.Error("PathEval_Compile: Expected cached eval")
	}

	got, err := eval.EvalInt(context.Background(), map[string]interface{}{"foo": 5})
	if err != nil {
		t.Error(err)
	}
	if got != 5 {
		t.Errorf("PathEval_Compile: Expected 5, got %v", got)
	}
}

func TestPathEval_Eval(t *testing.T) {
	pathEval := NewPathEval()
	_, err := pathEval.Eval("foo", nil)
	if err == nil {
		t.Error("PathEval_Eval: Expected error, got nil")
	}
	got, err := pathEval.Eval("foo", map[string]interface{}{"foo": 5})
	if err != nil {
		t.Error(err)
	}
	if got != 5 {
		t.Errorf("PathEval_Compile: Expected 5, got %v", got)
	}
}

func TestReMarshalMatcher(t *testing.T) {
	var intDst int
	var uintSrc uint = 2
	remarshalFunc := ReMarshalMatcher(&intDst)
	err := remarshalFunc(uintSrc)
	if err != nil {
		t.Error(err)
	}
	if intDst != 2 {
		t.Errorf("ReMarshalMatcher: Expected %v, got %v", uintSrc, intDst)
	}
}

func TestBoolMatcher(t *testing.T) {
	var boolDst bool
	boolFunc := BoolMatcher(&boolDst)
	err := boolFunc(true)
	if err != nil {
		t.Error(err)
	}

	if boolDst != true {
		t.Error("BoolMatcher: Expected true got false")
	}

	err = boolFunc(1)
	if err == nil {
		t.Error("BoolMatcher: Expected error, got nil")
	}
}

func TestStringMatcher(t *testing.T) {
	var stringDst string
	stringFunc := StringMatcher(&stringDst)
	err := stringFunc("test")
	if err != nil {
		t.Error(err)
	}

	if stringDst != "test" {
		t.Errorf("StringMatcher: Expected test, got %v", stringDst)
	}

	err = stringFunc(1)
	if err == nil {
		t.Error("StringMatcher: Expected error, got nil")
	}
}

func TestStringTreeMatcher(t *testing.T) {
	var stringTreeDst []string
	stringTreeFunc := StringTreeMatcher(&stringTreeDst)
	err := stringTreeFunc([]any{"a", "a", "b"})
	if err != nil {
		t.Error(err)
	}

	wantAnySlice := []any{"a", "b"}
	if reflect.DeepEqual(stringTreeDst, wantAnySlice) {
		t.Errorf("StringTreeMatcher: Expected %v, got %v", wantAnySlice, stringTreeDst)
	}

	err = stringTreeFunc([]string{"a", "a", "b"})
	if err == nil {
		t.Error("StringTreeMatcher: Expected error, got nil")
	}

	err = stringTreeFunc(1)
	if err == nil {
		t.Error("StringTreeMatcher: Expected error, got nil")
	}
}

func TestTimeMatcher(t *testing.T) {
	var timeDst time.Time
	timeFunc := TimeMatcher(&timeDst, time.RFC3339)
	err := timeFunc("2024-03-18T12:57:48.236Z")
	if err != nil {
		t.Error(err)
	}
	wantTime := time.Date(2024, time.March, 18, 12, 57, 48, 236_000_000, time.UTC)
	if timeDst != wantTime {
		t.Errorf("TimeMatcher: Expected %v, got %v", wantTime, timeDst)
	}

	err = timeFunc("")
	if err == nil {
		t.Error("TimeMatcher: Expected error, got nil")
	}

	err = timeFunc(1)
	if err == nil {
		t.Error("TimeMatcher: Expected error, got nil")
	}
}

func TestPathEval_Extract(t *testing.T) {
	pathEval := NewPathEval()
	var result string
	matcher := StringMatcher(&result)
	err := pathEval.Extract("foo", matcher, true, map[string]interface{}{"foo": "bar"})
	if err != nil {
		t.Error(err)
	}
	if result != "bar" {
		t.Errorf("PathEval_Extract: Expected bar, got %v", result)
	}
}

func TestPathEval_Match(t *testing.T) {
	var got string
	doc := map[string]interface{}{"foo": "bar"}

	pe := NewPathEval()
	pem := PathEvalMatcher{Expr: "foo", Action: StringMatcher(&got)}

	err := pe.Match([]PathEvalMatcher{pem}, doc)
	if err != nil {
		t.Error(err)
	}
	if got != "bar" {
		t.Errorf("PathEval_Match: Expected bar, got %v", got)
	}
}

func TestPathEval_Strings(t *testing.T) {
	pe := NewPathEval()
	doc := map[string]interface{}{"foo": "bar"}
	want := []string{"bar"}

	got, err := pe.Strings([]string{"foo"}, true, doc)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("PathEval_Strings: Expected %v, got %v", want, got)
	}
}

func TestAsStrings(t *testing.T) {
	arg := []interface{}{"foo", "bar"}
	want := []string{"foo", "bar"}

	got, valid := AsStrings(arg)
	if !valid {
		t.Error("AsStrings: Expected true, got false")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AsStrings: Expected %v, got %v", want, got)
	}
}

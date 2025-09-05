// Copyright 2015 RedHat, Inc.
// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdjournal

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/huntresslabs/go-systemd/journal"
)

func newJournal(t *testing.T) *Journal {
	t.Helper()
	j, err := NewJournal()
	if err != nil {
		t.Fatalf("Error opening journal: %s", err)
	}
	if j == nil {
		t.Fatal("Got a nil journal")
	}
	t.Cleanup(func() {
		if err := j.Close(); err != nil {
			t.Fatalf("Error closing journal: %s", err)
		}
	})
	return j
}

func TestJournalFollow(t *testing.T) {
	r, err := NewJournalReader(JournalReaderConfig{
		Since: time.Duration(-15) * time.Second,
		Matches: []Match{
			{
				Field: SD_JOURNAL_FIELD_SYSTEMD_UNIT,
				Value: "NetworkManager.service",
			},
		},
	})
	if err != nil {
		t.Fatalf("Error opening journal: %s", err)
	}

	if r == nil {
		t.Fatal("Got a nil reader")
	}

	defer r.Close()

	// start writing some test entries
	done := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				if perr := journal.Print(journal.PriInfo, "test message %s", time.Now()); err != nil {
					errCh <- perr
					return
				}

				time.Sleep(time.Second)
			}
		}
	}()

	// and follow the reader synchronously
	timeout := time.Duration(5) * time.Second
	if err = r.Follow(time.After(timeout), os.Stdout); err != ErrExpired {
		t.Fatalf("Error during follow: %s", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("Error writing to journal: %s", err)
	default:
	}
}

func TestJournalWait(t *testing.T) {
	j := newJournal(t)
	id := time.Now().String()
	if err := j.AddMatch("TEST=TestJournalWait " + id); err != nil {
		t.Fatalf("Error adding match: %s", err)
	}
	if err := j.SeekTail(); err != nil {
		t.Fatalf("Error seeking to tail: %s", err)
	}
	if _, err := j.Previous(); err != nil {
		t.Fatalf("Error retrieving previous entry: %s", err)
	}

	var t1, t2 time.Time
	for ret := -1; ret != SD_JOURNAL_NOP; {
		// Wait() might return for reasons other than timeout.
		// For example the first call initializes stuff and returns immediately.
		t1 = time.Now()
		ret = j.Wait(time.Millisecond * 300)
		t2 = time.Now()
	}
	duration := t2.Sub(t1)

	if duration > time.Millisecond*325 || duration < time.Millisecond*300 {
		t.Errorf("Wait did not wait 300ms. Actually waited %s", duration.String())
	}

	err := journal.Send("test message", journal.PriInfo, map[string]string{"TEST": "TestJournalWait " + id})
	if err != nil {
		t.Fatal(err)
	}
	for ret := -1; ret != SD_JOURNAL_APPEND; {
		t1 = time.Now()
		ret = j.Wait(time.Millisecond * 300)
		t2 = time.Now()
	}
	duration = t2.Sub(t1)

	if duration >= time.Millisecond*300 {
		t.Errorf("Wait took longer than 300ms. Actual duration %s", duration.String())
	}
}

func TestJournalGetUsage(t *testing.T) {
	j := newJournal(t)
	_, err := j.GetUsage()
	if err != nil {
		t.Fatalf("Error getting journal size: %s", err)
	}
}

func TestJournalCursorGetSeekAndTest(t *testing.T) {
	j := newJournal(t)

	err := journal.Print(journal.PriInfo, "test message for cursor %s", time.Now())
	if err != nil {
		t.Fatalf("Error writing to journal: %s", err)
	}
	waitAndNext(t, j)

	c, err := j.GetCursor()
	if err != nil {
		t.Fatalf("Error getting cursor from journal: %s", err)
	}

	err = j.SeekCursor(c)
	if err != nil {
		t.Fatalf("Error seeking cursor to journal: %s", err)
	}
	waitAndNext(t, j)

	err = j.TestCursor(c)
	if err != nil {
		t.Fatalf("Error testing cursor to journal: %s", err)
	}

	err = journal.Print(journal.PriInfo, "second message %s", time.Now())
	if err != nil {
		t.Fatalf("Error writing to journal: %s", err)
	}
	waitAndNext(t, j)

	err = j.TestCursor(c)
	if err != ErrNoTestCursor {
		t.Fatalf("Error, TestCursor should fail because current cursor has moved from the previous obtained cursor")
	}
}

func TestNewJournalFromDir(t *testing.T) {
	// test for error handling
	dir := "/ClearlyNonExistingPath/"
	j, err := NewJournalFromDir(dir)
	if err == nil {
		j.Close()
		t.Fatalf("Error expected when opening dummy path (%s)", dir)
	}
	// test for main code path
	dir = t.TempDir()
	j, err = NewJournalFromDir(dir)
	if err != nil {
		t.Fatalf("Error opening journal: %s", err)
	}
	if j == nil {
		t.Fatal("Got a nil journal")
	}
	j.Close()
}

func setupJournalRoundtrip(t *testing.T) (*Journal, map[string]string) {
	t.Helper()
	j := newJournal(t)

	j.FlushMatches()

	matchField := "TESTJOURNALENTRY"
	matchValue := fmt.Sprintf("%d", time.Now().UnixNano())
	m := Match{Field: matchField, Value: matchValue}
	err := j.AddMatch(m.String())
	if err != nil {
		t.Fatalf("Error adding matches to journal: %s", err)
	}

	msg := fmt.Sprintf("test journal get entry message %s", time.Now())
	data := map[string]string{matchField: matchValue}
	err = journal.Send(msg, journal.PriInfo, data)
	if err != nil {
		t.Fatalf("Error writing to journal: %s", err)
	}

	time.Sleep(time.Duration(1) * time.Second)

	n, err := j.Next()
	if err != nil {
		t.Fatalf("Error reading from journal: %s", err)
	}

	if n == 0 {
		t.Fatalf("Error reading from journal: %s", io.EOF)
	}

	data["MESSAGE"] = msg

	return j, data
}

func TestJournalGetData(t *testing.T) {
	j, wantEntry := setupJournalRoundtrip(t)
	for k, v := range wantEntry {
		data := fmt.Sprintf("%s=%s", k, v)

		dataStr, err := j.GetData(k)
		if err != nil {
			t.Fatalf("GetData() error: %v", err)
		}

		if dataStr != data {
			t.Fatalf("Invalid data for %q: got %s, want %s", k, dataStr, data)
		}

		dataBytes, err := j.GetDataBytes(k)
		if err != nil {
			t.Fatalf("GetDataBytes() error: %v", err)
		}

		if string(dataBytes) != data {
			t.Fatalf("Invalid data bytes for %q: got %s, want %s", k, string(dataBytes), data)
		}

		valStr, err := j.GetDataValue(k)
		if err != nil {
			t.Fatalf("GetDataValue() error: %v", err)
		}

		if valStr != v {
			t.Fatalf("Invalid data value for %q: got %s, want %s", k, valStr, v)
		}

		valBytes, err := j.GetDataValueBytes(k)
		if err != nil {
			t.Fatalf("GetDataValueBytes() error: %v", err)
		}

		if string(valBytes) != v {
			t.Fatalf("Invalid data value bytes for %q: got %s, want %s", k, string(valBytes), v)
		}
	}
}

func TestJournalGetEntry(t *testing.T) {
	j, wantEntry := setupJournalRoundtrip(t)
	entry, err := j.GetEntry()
	if err != nil {
		t.Fatalf("Error getting the entry to journal: %s", err)
	}

	for k, wantV := range wantEntry {
		gotV := entry.Fields[k]
		if gotV != wantV {
			t.Fatalf("Bad result for entry.Fields[%q]: got %s, want %s", k, gotV, wantV)
		}
	}
}

// Check for incorrect read into small buffers,
// see https://github.com/coreos/go-systemd/issues/172
func TestJournalReaderSmallReadBuffer(t *testing.T) {
	// Write a long entry ...
	delim := "%%%%%%"
	longEntry := strings.Repeat("a", 256)
	matchField := "TESTJOURNALREADERSMALLBUF"
	matchValue := fmt.Sprintf("%d", time.Now().UnixNano())
	r, err := NewJournalReader(JournalReaderConfig{
		Since: time.Duration(-15) * time.Second,
		Matches: []Match{
			{
				Field: matchField,
				Value: matchValue,
			},
		},
	})
	if err != nil {
		t.Fatalf("Error opening journal: %s", err)
	}
	if r == nil {
		t.Fatal("Got a nil reader")
	}
	defer r.Close()

	want := fmt.Sprintf("%slongentry %s%s", delim, longEntry, delim)
	err = journal.Send(want, journal.PriInfo, map[string]string{matchField: matchValue})
	if err != nil {
		t.Fatal("Error writing to journal", err)
	}
	time.Sleep(time.Second)

	// ... and try to read it back piece by piece via a small buffer
	finalBuff := new(bytes.Buffer)
	var e error
	for c := -1; c != 0 && e == nil; {
		smallBuf := make([]byte, 5)
		c, e = r.Read(smallBuf)
		if c > len(smallBuf) {
			t.Fatalf("Got unexpected read length: %d vs %d", c, len(smallBuf))
		}
		_, _ = finalBuff.Write(smallBuf)
	}
	b := finalBuff.String()
	got := strings.Split(b, delim)
	if len(got) != 3 {
		t.Fatalf("Got unexpected entry %s", b)
	}
	if got[1] != strings.Trim(want, string(delim[0])) {
		t.Fatalf("Got unexpected message %s", got[1])
	}
}

func TestJournalGetUniqueValues(t *testing.T) {
	j := newJournal(t)

	uniqueString := generateRandomField(20)
	testEntries := []string{"A", "B", "C", "D"}
	for _, v := range testEntries {
		err := journal.Send("TEST: "+uniqueString, journal.PriInfo, map[string]string{uniqueString: v})
		if err != nil {
			t.Fatal(err)
		}
	}

	// TODO: add proper `waitOnMatch` function which should wait for journal entry with filter to commit.
	time.Sleep(time.Millisecond * 500)

	values, err := j.GetUniqueValues(uniqueString)
	if err != nil {
		t.Fatal(err)
	}

	if len(values) != len(testEntries) {
		t.Fatalf("Expect %d entries. Got %d", len(testEntries), len(values))
	}

	for _, exp := range testEntries {
		if !slices.Contains(values, exp) {
			t.Fatalf("Expect %v to contain %s", values, exp)
		}
	}
}

func TestJournalGetCatalog(t *testing.T) {
	want := []string{
		"Subject: ",
		"Defined-By: systemd",
		"Support: ",
	}
	j := newJournal(t)

	if err := j.SeekHead(); err != nil {
		t.Fatalf("Seek to head failed: %s", err)
	}

	matchField := SD_JOURNAL_FIELD_SYSTEMD_UNIT
	m := Match{Field: matchField, Value: "systemd-journald.service"}
	if err := j.AddMatch(m.String()); err != nil {
		t.Fatalf("Error adding matches to journal: %s", err)
	}

	// Look for an entry with MESSAGE_ID (required for GetCatalog).
	found := false
	for range 100 {
		n, err := j.Next()
		if err != nil {
			t.Fatalf("Error reading journal: %s", err)
		}
		if n == 0 {
			break
		}

		// Check if this entry has a MESSAGE_ID
		if _, err := j.GetData("MESSAGE_ID"); err == nil {
			found = true
			break
		}
	}

	if !found {
		t.Skip("No journal entries with MESSAGE_ID found for systemd-journald.service")
	}

	catalog, err := j.GetCatalog()
	if err != nil {
		t.Fatalf("Failed to retrieve catalog entry: %s", err)
	}

	for _, w := range want {
		if !strings.Contains(catalog, w) {
			t.Fatalf("Failed to find %q in \n%s", w, catalog)
		}
	}
}

func TestJournalGetBootID(t *testing.T) {
	j := newJournal(t)

	bootID, err := j.GetBootID()
	if err != nil {
		t.Fatalf("Failed to get bootID : %s", err)
	}

	if len(bootID) <= 0 {
		t.Fatalf("Get bootID: %s is Null", bootID)
	}

	t.Log("bootid:", bootID)
}

func generateRandomField(n int) string {
	letters := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func waitAndNext(t *testing.T, j *Journal) {
	t.Helper()
	r := j.Wait(time.Duration(1) * time.Second)
	if r < 0 {
		t.Fatal("Error waiting to journal")
	}

	n, err := j.Next()
	if err != nil {
		t.Fatalf("Error reading to journal: %s", err)
	}

	if n == 0 {
		t.Fatalf("Error reading to journal: %s", io.EOF)
	}
}
